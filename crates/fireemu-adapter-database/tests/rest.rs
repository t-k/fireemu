//! The REST API, request by request. Unless a test says otherwise, every expected status,
//! header and body is what the official emulator (firebase-database-emulator v4.11.2) answered
//! to the same request.

#![allow(clippy::too_many_lines, clippy::items_after_statements)]

use fireemu_adapter_database::rest::{
    Database, Handled, HttpRequest, HttpResponse, RestOptions, RulesMode,
};
use fireemu_core_database::Path;

const NOW: i64 = 1_792_408_481_564;

fn db() -> Database {
    Database::new(RestOptions::default(), 42)
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

fn send(
    db: &mut Database,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    match db.handle(&request(method, target, headers, body), NOW) {
        Handled::Response { response, .. } => response,
        Handled::Stream { .. } => panic!("unexpected stream for {method} {target}"),
    }
}

fn call(db: &mut Database, method: &str, target: &str, body: &str) -> (u16, String) {
    let response = send(db, method, target, &[], body);
    (response.status, String::from_utf8(response.body).unwrap())
}

fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn error(message: &str) -> String {
    format!(
        "{{\n  \"error\" : \"{}\"\n}}\n",
        message.replace('"', "\\\"")
    )
}

#[test]
fn put_get_patch_delete_round_trip() {
    let mut db = db();
    assert_eq!(
        call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1,"y":{"z":"s"}}"#),
        (200, r#"{"x":1,"y":{"z":"s"}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1", ""),
        (200, r#"{"x":1,"y":{"z":"s"}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "PATCH", "/a.json?ns=t1", r#"{"y/z":"t","w":3}"#),
        (200, r#"{"y":{"z":"t"},"w":3}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "DELETE", "/a/y.json?ns=t1", ""),
        (200, "null".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1", ""),
        (200, r#"{"w":3,"x":1}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/missing.json?ns=t1", ""),
        (200, "null".to_owned())
    );
}

#[test]
fn json_answers_carry_the_server_headers() {
    let mut db = db();
    let response = send(&mut db, "GET", "/a.json?ns=t1", &[], "");
    assert_eq!(
        header(&response, "Content-Type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(header(&response, "Access-Control-Allow-Origin"), Some("*"));
    assert_eq!(header(&response, "Cache-Control"), Some("no-cache"));
    assert_eq!(header(&response, "ETag"), None);
}

#[test]
fn namespaces_are_isolated() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=one", "1");
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=two", ""),
        (200, "null".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=one", ""),
        (200, "1".to_owned())
    );
    assert!(db.tree("one").unwrap().get(&Path::root()).is_some());
}

#[test]
fn the_namespace_comes_from_ns_then_the_host_then_the_default() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=q1", "1");
    fn host(h: &str) -> (&str, &str) {
        ("Host", h)
    }
    let mut get = |headers: &[(&str, &str)], target: &str| {
        String::from_utf8(send(&mut db, "GET", target, headers, "").body).unwrap()
    };
    assert_eq!(get(&[host("q1.firebaseio.com")], "/a.json"), "1");
    assert_eq!(
        get(&[host("q1.europe-west1.firebasedatabase.app")], "/a.json"),
        "1"
    );
    assert_eq!(get(&[host("q1.localhost:9000")], "/a.json"), "1");
    assert_eq!(get(&[host("Q1.firebaseio.com")], "/a.json"), "1");
    assert_eq!(get(&[host("other.firebaseio.com")], "/a.json?ns=q1"), "1");
    assert_eq!(get(&[host("localhost:9000")], "/a.json"), "null");
    assert_eq!(get(&[host("127.0.0.1:9000")], "/a.json"), "null");
    call(&mut db, "PUT", "/a.json", "7");
    let mut get = |headers: &[(&str, &str)], target: &str| {
        String::from_utf8(send(&mut db, "GET", target, headers, "").body).unwrap()
    };
    assert_eq!(get(&[host("127.0.0.1:9000")], "/a.json"), "7");
    assert_eq!(get(&[host("localhost")], "/a.json"), "7");
    assert_eq!(get(&[], "/a.json?ns=Q1"), "1");
    call(&mut db, "PUT", "/d.json", "2");
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=fake-server", ""),
        (200, "2".to_owned())
    );
}

#[test]
fn a_malformed_percent_escape_anywhere_in_the_target_is_a_bad_request() {
    let mut db = db();
    // Refused before the namespace, the method and the .json suffix are looked at.
    for (method, target) in [
        ("GET", "/x%zz.json?ns=hyg"),
        ("GET", "/x%4.json?ns=hyg"),
        ("GET", "/x%+f.json?ns=hyg"),
        ("PUT", "/x%zz.json?ns=hyg"),
        ("GET", "/x.json?ns=hyg&a=%zz"),
        ("GET", "/x.json?ns=hyg&a=%2"),
        ("GET", "/x.json?ns=hyg&a=%+f"),
        ("GET", "/x.json?ns=hyg%zz"),
        ("GET", "/x%zz?ns=hyg"),
        ("TRACE", "/x.json?ns=hyg&a=%"),
    ] {
        assert_eq!(
            call(&mut db, method, target, "1"),
            (400, error("Bad Request")),
            "{method} {target}"
        );
    }
    // A well-formed escape of a byte that is not UTF-8, or of a percent sign, is not.
    assert_eq!(call(&mut db, "GET", "/x%FF.json?ns=hyg", "").0, 200);
    assert_eq!(call(&mut db, "GET", "/x.json?ns=hyg&a=%FF", "").0, 200);
    assert_eq!(
        call(&mut db, "PUT", "/x%25zz.json?ns=hyg", "1"),
        (200, "1".to_owned())
    );
    assert_eq!(call(&mut db, "GET", "/.json?ns=hyg", "").1, r#"{"x%zz":1}"#);
}

#[test]
fn invalid_namespaces_are_forbidden() {
    let mut db = db();
    for ns in ["Bad_NS", "", "a.b", "-a", "a_b"] {
        assert_eq!(
            call(&mut db, "GET", &format!("/x.json?ns={ns}"), ""),
            (403, error("Invalid Firebase database name")),
            "{ns:?}"
        );
    }
    for ns in [
        "a-b",
        "1abc",
        "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop",
    ] {
        assert_eq!(
            call(&mut db, "GET", &format!("/x.json?ns={ns}"), "").0,
            200,
            "{ns:?}"
        );
    }
}

#[test]
fn urls_must_end_in_dot_json() {
    let mut db = db();
    let response = send(&mut db, "GET", "/d/a?ns=q1", &[], "");
    assert_eq!(response.status, 400);
    assert_eq!(header(&response, "Content-Type"), Some("text/plain"));
    assert_eq!(
        response.body,
        b"Append .json to your URL to use the REST API."
    );
}

#[test]
fn invalid_paths_are_refused() {
    let mut db = db();
    let token = error("Invalid path: Invalid token in path");
    assert_eq!(
        call(&mut db, "PUT", "/b$ad.json?ns=t1", "1"),
        (400, token.clone())
    );
    assert_eq!(
        call(&mut db, "PUT", "/.info/x.json?ns=t1", "1"),
        (400, token.clone())
    );
    assert_eq!(
        call(&mut db, "GET", "/.info.json?ns=t1", ""),
        (400, token.clone())
    );
    assert_eq!(
        call(&mut db, "PUT", "/x/.priority/y.json?ns=t1", "5"),
        (400, token)
    );
    let deep = (0..33)
        .map(|i| format!("k{i}"))
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        call(&mut db, "PUT", &format!("/{deep}.json?ns=v1"), "1"),
        (
            400,
            error(
                "Invalid path: Path specified exceeds the maximum depth that can be written (32)."
            )
        )
    );
    let shallow = (0..32)
        .map(|i| format!("k{i}"))
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        call(&mut db, "PUT", &format!("/{shallow}.json?ns=v1"), "1").0,
        200
    );
    assert_eq!(
        call(&mut db, "PUT", &format!("/{}.json?ns=v1", "a".repeat(769)), "1"),
        (400, error("Invalid path: Path specified exceeds the maximum length that can be written (768 bytes)."))
    );
}

#[test]
fn percent_encoded_paths_are_decoded() {
    let mut db = db();
    assert_eq!(call(&mut db, "PUT", "/a%20b.json?ns=v1", "1").0, 200);
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=v1", ""),
        (200, r#"{"a b":1}"#.to_owned())
    );
    // An encoded slash separates keys like a plain one.
    assert_eq!(call(&mut db, "PUT", "/a%2Fb.json?ns=v2", "1").0, 200);
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=v2", ""),
        (200, r#"{"b":1}"#.to_owned())
    );
}

#[test]
fn settings_are_forbidden_without_an_administrator_credential() {
    let mut db = db();
    assert_eq!(
        call(&mut db, "GET", "/.settings/rules.json?ns=q1", ""),
        (403, error("Permission denied."))
    );
}

#[test]
fn write_bodies_are_checked() {
    let mut db = db();
    let parse = error("Invalid data; couldn't parse JSON object, array, or value.");
    let key = |at: &str| {
        error(&format!(
            "Invalid data; couldn't parse key beginning at {at}. Key value can't be empty or contain $ # [ ] / or ."
        ))
    };
    assert_eq!(
        call(&mut db, "PUT", "/bad.json?ns=t1", r#"{"a.b":1}"#),
        (400, key("1:2"))
    );
    assert_eq!(
        call(&mut db, "PUT", "/bad.json?ns=t1", "{bad json"),
        (400, parse.clone())
    );
    assert_eq!(
        call(&mut db, "PUT", "/bad.json?ns=t1", ""),
        (400, error("No data supplied."))
    );
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=v1", r#"{"a":{"b":{"c.d":1}}}"#),
        (400, key("1:12"))
    );
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=v1", "{\n  \"a\" : {\"b$\":1}}"),
        (400, key("2:10"))
    );
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=v1", r#"{".other":1}"#),
        (400, key("1:2"))
    );
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=v1", r#"{"":1}"#),
        (400, key("1:2"))
    );
    assert_eq!(
        call(&mut db, "PUT", "/f.json?ns=q1", r#"{"x":{"y":1},"x/z":2}"#),
        (400, key("1:14"))
    );
    for body in [
        r#"{"a":1,".priority":true}"#,
        r#"{".value":1,"a":2}"#,
        r#"{".sv":"timestamp","x":1}"#,
        r#"{".sv":{"increment":"1"}}"#,
        r#"{".sv":"nope"}"#,
    ] {
        assert_eq!(
            call(&mut db, "PUT", "/x.json?ns=v1", body),
            (400, parse.clone()),
            "{body}"
        );
    }
    let shallow = (0..32)
        .map(|i| format!("k{i}"))
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        call(
            &mut db,
            "PUT",
            &format!("/{shallow}.json?ns=v1"),
            r#"{"a":1}"#
        ),
        (400, parse.clone())
    );
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/x.json?ns=v1",
            &format!(r#"{{"{}":1}}"#, "a".repeat(768))
        ),
        (400, parse)
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=v1", ""),
        (200, "null".to_owned())
    );
}

#[test]
fn put_answers_and_tags_the_value_as_written_even_when_nothing_is_stored() {
    let mut db = db();
    let etag = |db: &mut Database, method: &str, target: &str, body: &str| {
        header(
            &send(db, method, target, &[("X-Firebase-ETag", "true")], body),
            "ETag",
        )
        .unwrap()
        .to_owned()
    };
    // The increment resolves to the double 1.0; the stored 1 stays, being equal.
    call(&mut db, "PUT", "/c.json?ns=w2", "1");
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/c.json?ns=w2",
            r#"{".sv":{"increment":0.0}}"#
        ),
        (200, "1.0".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/c.json?ns=w2", ""),
        (200, "1".to_owned())
    );
    let resolved = r#"{"a":{".sv":{"increment":0}},"b":1}"#;
    call(
        &mut db,
        "PUT",
        "/n.json?ns=w2",
        r#"{"a":{".sv":{"increment":2}},"b":1.0}"#,
    );
    assert_eq!(
        call(&mut db, "PUT", "/n.json?ns=w2", resolved),
        (200, r#"{"a":2,"b":1}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/n.json?ns=w2", ""),
        (200, r#"{"a":2,"b":1.0}"#.to_owned())
    );
    // The answer's ETag hashes what was written (0), not what stays stored (-0.0).
    call(&mut db, "PUT", "/z.json?ns=w2", "-0.0");
    call(&mut db, "PUT", "/y.json?ns=w2", "0");
    let zero = etag(&mut db, "GET", "/y.json?ns=w2", "");
    let negative_zero = etag(&mut db, "GET", "/z.json?ns=w2", "");
    assert_eq!(zero, "7ysMph9WPitGP7poMnMHMVPtUlI=");
    assert_eq!(negative_zero, "m/gA365Q5OBo06Bg8wdybAAiMSQ=");
    assert_eq!(etag(&mut db, "PUT", "/z.json?ns=w2", "0"), zero);
    assert_eq!(etag(&mut db, "GET", "/z.json?ns=w2", ""), negative_zero);
}

#[test]
fn put_answers_the_stored_value_in_export_form() {
    let mut db = db();
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/p.json?ns=t1",
            r#"{".value":1,".priority":2}"#
        ),
        (200, r#"{".value":1,".priority":2.0}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/p.json?ns=t1", ""),
        (200, "1".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/p.json?ns=t1&format=export", ""),
        (200, r#"{".value":1,".priority":2.0}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/p/.priority.json?ns=t1", ""),
        (200, "2.0".to_owned())
    );
    assert_eq!(
        call(&mut db, "PUT", "/arr.json?ns=t1", r#"["a","b",null,"d"]"#),
        (200, r#"["a","b",null,"d"]"#.to_owned())
    );
    call(&mut db, "PUT", "/x.json?ns=t1", r#"{"b":2}"#);
    assert_eq!(
        call(&mut db, "PUT", "/x/.priority.json?ns=t1", "5"),
        (200, "5".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/x.json?ns=t1&format=export", "").1,
        r#"{".priority":5,"b":2}"#
    );
    // A leaf's priority reads as a double; the write itself answers what was written.
    call(&mut db, "PUT", "/l.json?ns=t1", "1");
    assert_eq!(
        call(&mut db, "PUT", "/l/.priority.json?ns=t1", "5"),
        (200, "5".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/l.json?ns=t1&format=export", "").1,
        r#"{".value":1,".priority":5.0}"#
    );
    assert_eq!(
        call(&mut db, "GET", "/l/.priority.json?ns=t1", ""),
        (200, "5.0".to_owned())
    );
    assert_eq!(
        call(&mut db, "PATCH", "/.json?ns=t1", r#"{"l/.priority":4}"#).1,
        r#"{"l":{".priority":4}}"#
    );
    assert_eq!(
        call(&mut db, "GET", "/l.json?ns=t1&format=export", "").1,
        r#"{".value":1,".priority":4.0}"#
    );
    assert_eq!(
        call(&mut db, "PUT", "/x/.priority.json?ns=t1", "true"),
        (
            400,
            error("Invalid data; couldn't parse JSON object, array, or value.")
        )
    );
}

#[test]
fn server_values_resolve_at_the_request_time() {
    let mut db = db();
    assert_eq!(
        call(&mut db, "PUT", "/ts.json?ns=t1", r#"{".sv":"timestamp"}"#),
        (200, NOW.to_string())
    );
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/ts.json?ns=t1",
            r#"{".sv":{"increment":2}}"#
        ),
        (200, (NOW + 2).to_string())
    );
    assert_eq!(
        call(
            &mut db,
            "PATCH",
            "/x.json?ns=v1",
            r#"{"t":{".sv":"timestamp"}}"#
        ),
        (200, format!(r#"{{"t":{NOW}}}"#))
    );
}

#[test]
fn post_creates_increasing_push_ids() {
    let mut db = db();
    let (status, first) = call(&mut db, "POST", "/list.json?ns=t1", r#""v""#);
    assert_eq!(status, 200);
    let (_, second) = call(&mut db, "POST", "/list.json?ns=t1", r#""w""#);
    let id = |body: &str| {
        body.trim_start_matches(r#"{"name":""#)
            .trim_end_matches(r#""}"#)
            .to_owned()
    };
    let (a, b) = (id(&first), id(&second));
    assert_eq!(a.len(), 20);
    assert!(a < b);
    assert_eq!(
        call(&mut db, "GET", "/list.json?ns=t1", ""),
        (200, format!(r#"{{"{a}":"v","{b}":"w"}}"#))
    );
}

#[test]
fn patch_needs_an_object_with_valid_disjoint_paths() {
    let mut db = db();
    let message = error("Invalid data; couldn't parse JSON object. Are you sending a JSON object with valid key names?");
    for body in [
        r#"{"q":1,"q/r":2}"#,
        "[1,2]",
        "5",
        r#"{"a.b":1}"#,
        r#"{"a":{"b.c":1}}"#,
        r#"{"/":1}"#,
    ] {
        assert_eq!(
            call(&mut db, "PATCH", "/x.json?ns=v1", body),
            (400, message.clone()),
            "{body}"
        );
    }
    assert_eq!(
        call(&mut db, "PATCH", "/x.json?ns=v1", "{}"),
        (200, "{}".to_owned())
    );
    assert_eq!(
        call(&mut db, "PATCH", "/x.json?ns=v1", r#"{"a//b":1}"#),
        (200, r#"{"a":{"b":1}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "PATCH", "/x.json?ns=v1", r#"{"a":null,"b":2}"#),
        (200, r#"{"a":null,"b":2}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/x.json?ns=v1", ""),
        (200, r#"{"b":2}"#.to_owned())
    );
}

#[test]
fn etags_and_conditional_writes() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1,"y":{"z":"s"}}"#);
    let response = send(
        &mut db,
        "GET",
        "/a.json?ns=t1",
        &[("X-Firebase-ETag", "true")],
        "",
    );
    assert_eq!(
        header(&response, "ETag"),
        Some("6CNhL/bRBr4qg3PQLZRyxlcsmkg=")
    );
    assert_eq!(
        header(&response, "Access-Control-Expose-Headers"),
        Some("ETag")
    );
    let response = send(
        &mut db,
        "GET",
        "/missing.json?ns=t1",
        &[("X-Firebase-ETag", "true")],
        "",
    );
    assert_eq!(header(&response, "ETag"), Some("null_etag"));

    let refused = send(
        &mut db,
        "PUT",
        "/a/x.json?ns=t1",
        &[("if-match", "wrong")],
        "2",
    );
    assert_eq!(refused.status, 412);
    assert_eq!(refused.body, b"1");
    assert_eq!(
        header(&refused, "ETag"),
        Some("YPVfR2bXt/lcDjiQZ8pOkAd3qkQ=")
    );

    let accepted = send(
        &mut db,
        "PUT",
        "/a/x.json?ns=t1",
        &[("if-match", "YPVfR2bXt/lcDjiQZ8pOkAd3qkQ=")],
        "2",
    );
    assert_eq!(
        (accepted.status, accepted.body.as_slice()),
        (200, &b"2"[..])
    );
    assert_eq!(
        send(
            &mut db,
            "PUT",
            "/new.json?ns=t1",
            &[("if-match", "null_etag")],
            "5"
        )
        .status,
        200
    );

    let deleted = send(
        &mut db,
        "DELETE",
        "/zz.json?ns=q1",
        &[("if-match", "wrong")],
        "",
    );
    assert_eq!(
        (deleted.status, header(&deleted, "ETag")),
        (412, Some("null_etag"))
    );

    let unsupported =
        error("The 'if-match' header is not supported with GET, PATCH or POST requests");
    for method in ["GET", "PATCH", "POST"] {
        let response = send(
            &mut db,
            method,
            "/zz.json?ns=q1",
            &[("if-match", "null_etag")],
            r#"{"a":1}"#,
        );
        assert_eq!(response.status, 400, "{method}");
        assert_eq!(String::from_utf8(response.body).unwrap(), unsupported);
    }

    let written = send(
        &mut db,
        "PUT",
        "/d/a/h.json?ns=q1",
        &[("X-Firebase-ETag", "true")],
        "7",
    );
    assert_eq!(
        header(&written, "ETag"),
        Some("7wQgMram7RVqVIg/xRZWPfygGx0=")
    );
    let silent = send(
        &mut db,
        "PUT",
        "/x.json?ns=v1&print=silent",
        &[("X-Firebase-ETag", "true")],
        "1",
    );
    assert_eq!(
        (silent.status, header(&silent, "ETag")),
        (204, Some("YPVfR2bXt/lcDjiQZ8pOkAd3qkQ="))
    );
}

#[test]
fn print_shallow_export_callback_and_download() {
    let mut db = db();
    call(
        &mut db,
        "PUT",
        "/a.json?ns=t1",
        r#"{"w":3,"x":1,"y":{"z":"t"}}"#,
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&print=pretty", ""),
        (
            200,
            "{\n  \"w\" : 3,\n  \"x\" : 1,\n  \"y\" : {\n    \"z\" : \"t\"\n  }\n}\n".to_owned()
        )
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&print=bogus", "").1,
        r#"{"w":3,"x":1,"y":{"z":"t"}}"#
    );
    for method in ["GET", "PUT", "POST", "PATCH", "DELETE"] {
        let body = if method == "PATCH" { r#"{"q":1}"# } else { "1" };
        let response = send(&mut db, method, "/s.json?ns=t1&print=silent", &[], body);
        assert_eq!((response.status, response.body.len()), (204, 0), "{method}");
    }
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&shallow=true", ""),
        (200, r#"{"w":true,"x":true,"y":true}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/a/x.json?ns=t1&shallow=true", ""),
        (200, "1".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&shallow=yes", "").1,
        r#"{"w":3,"x":1,"y":{"z":"t"}}"#
    );
    call(
        &mut db,
        "PUT",
        "/e.json?ns=t1",
        r#"{"k":{".value":"v",".priority":"p"},".priority":1}"#,
    );
    assert_eq!(
        call(&mut db, "GET", "/e.json?ns=t1&format=export", "").1,
        r#"{".priority":1.0,"k":{".value":"v",".priority":"p"}}"#
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/e.json?ns=t1&shallow=true&format=export",
            ""
        )
        .1,
        r#"{".priority":true,"k":true}"#
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&format=bogus", ""),
        (400, error("Export format must be export if present"))
    );

    let jsonp = send(&mut db, "GET", "/a/x.json?ns=t1&callback=cb", &[], "");
    assert_eq!(
        header(&jsonp, "Content-Type"),
        Some("application/javascript; charset=utf-8")
    );
    assert_eq!(jsonp.body, b"/**/ cb(1);");
    let download = send(&mut db, "GET", "/a/x.json?ns=t1&download=f.json", &[], "");
    assert_eq!(
        header(&download, "Content-Disposition"),
        Some("attachment; filename=\"f.json\"")
    );
    assert_eq!(
        header(&download, "Content-Type"),
        Some("application/octet-stream; charset=utf-8")
    );
    assert_eq!(download.body, b"1");
}

#[test]
fn method_override_options_and_unsupported_methods() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1}"#);
    let deleted = send(
        &mut db,
        "POST",
        "/a/x.json?ns=t1",
        &[("X-HTTP-Method-Override", "DELETE")],
        "",
    );
    assert_eq!(
        (deleted.status, deleted.body.as_slice()),
        (200, &b"null"[..])
    );
    let options = send(&mut db, "OPTIONS", "/a.json?ns=t1", &[], "");
    assert_eq!(options.status, 200);
    assert_eq!(
        header(&options, "Allow"),
        Some("OPTIONS,GET,POST,PUT,DELETE,PATCH")
    );
    assert_eq!(
        header(&options, "Access-Control-Allow-Methods"),
        Some("OPTIONS,GET,POST,PUT,DELETE,PATCH")
    );
    assert_eq!(
        call(&mut db, "HEAD", "/a.json?ns=t1", ""),
        (405, error("Unsupported request type"))
    );
}

#[test]
fn write_size_limit_values_are_checked() {
    let mut db = db();
    for limit in ["tiny", "small", "medium", "large", "unlimited"] {
        assert_eq!(
            call(
                &mut db,
                "PUT",
                &format!("/a.json?ns=q1&writeSizeLimit={limit}"),
                "1"
            )
            .0,
            200
        );
    }
    assert_eq!(
        call(&mut db, "PUT", "/a.json?ns=q1&writeSizeLimit=bogus", "1"),
        (
            400,
            error("writeSizeLimit should be one of {medium, tiny, large, unlimited, small}")
        )
    );
}

fn query_db() -> Database {
    let mut db = db();
    call(
        &mut db,
        "PUT",
        "/d.json?ns=q1",
        r#"{"a":{"h":3,"n":"x"},"b":{"h":1},"c":{"h":2},"d":{"n":"y"},"10":{"h":5},"2":{"h":5}}"#,
    );
    db
}

#[test]
fn query_parameters_need_order_by_and_valid_values() {
    let mut db = query_db();
    let cases = [
        ("limitToFirst=2", "orderBy must be defined when other query parameters are defined"),
        ("startAt=2", "orderBy must be defined when other query parameters are defined"),
        ("orderBy=h", "orderBy must be a valid JSON encoded path"),
        ("orderBy=\"$bad\"", "orderBy must be a valid JSON encoded path"),
        ("orderBy=\"a.b\"", "orderBy must be a valid JSON encoded path"),
        ("orderBy=\"h\"&startAt=5&startAfter=1", "Only one of startAfter and startAt may be specified"),
        ("orderBy=\"h\"&endAt=5&endBefore=1", "Only one of endAt and endBefore may be specified"),
        ("orderBy=\"$key\"&startAt=\"a\"&equalTo=\"a\"", "equalTo cannot be specified in addition to startAfter, startAt, endAt, or endBefore"),
        ("orderBy=\"h\"&limitToFirst=0", "limitToFirst must be positive"),
        ("orderBy=\"h\"&limitToFirst=-1", "limitToFirst must be positive"),
        ("orderBy=\"$key\"&limitToFirst=1.5", "limitToFirst must be an integer"),
        ("orderBy=\"$key\"&limitToLast=abc", "limitToLast must be an integer"),
        ("orderBy=\"h\"&limitToFirst=2&limitToLast=2", "Only one of limitToFirst and limitToLast may be specified"),
        ("orderBy=\"h\"&startAt=x", "Constraint index field must be a JSON primitive"),
        ("orderBy=\"$key\"&startAt=2", "Provided key index type is invalid, must be string"),
        ("orderBy=\"$key\"&startAt=null", "Provided key index type is invalid, must be string"),
        ("orderBy=\"$key\"&startAt=\"a\",\"b\"", "Too many parameters for key index"),
        ("orderBy=\"h\"&shallow=true", "orderBy not supported for with shallow GET, keys are returned in lexicographical order"),
    ];
    for (query, message) in cases {
        assert_eq!(
            call(&mut db, "GET", &format!("/d.json?ns=q1&{query}"), ""),
            (400, error(message)),
            "{query}"
        );
    }
    assert_eq!(
        call(&mut db, "PUT", "/d.json?ns=q1&orderBy=\"$key\"", "1"),
        (
            400,
            error("Querying related parameters not supported on this request type")
        )
    );
}

#[test]
fn child_and_value_orders_need_a_declared_index() {
    let mut db = query_db();
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"h\"", ""),
        (
            400,
            error("Index not defined, add \".indexOn\": \"h\", for path \"/d\", to the rules")
        )
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/d.json?ns=q1&orderBy=\"$value\"&limitToFirst=2",
            ""
        ),
        (
            400,
            error("Index not defined, add \".indexOn\": \".value\", for path \"/d\", to the rules")
        )
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"n/q\"", ""),
        (
            400,
            error("Index not defined, add \".indexOn\": \"n/q\", for path \"/d\", to the rules")
        )
    );
    // Not observed on the official emulator (it has no rules here): a declared index serves
    // the query.
    db.declare_index("q1", &Path::from_keys(["d"]), "h");
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/d.json?ns=q1&orderBy=\"h\"&startAt=2&limitToFirst=2",
            ""
        ),
        (
            200,
            r#"{"a":{"h":3},"c":{"h":2}}"#.replace(r#"{"h":3}"#, r#"{"h":3,"n":"x"}"#)
        )
    );
}

#[test]
fn key_and_priority_queries() {
    let mut db = query_db();
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/d.json?ns=q1&orderBy=\"$key\"&startAt=\"b\"",
            ""
        ),
        (200, r#"{"b":{"h":1},"c":{"h":2},"d":{"n":"y"}}"#.to_owned())
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/d.json?ns=q1&orderBy=\"$key\"&limitToFirst=2",
            ""
        ),
        (200, r#"{"2":{"h":5},"10":{"h":5}}"#.to_owned())
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/d.json?ns=q1&orderBy=\"$priority\"&limitToFirst=2",
            ""
        ),
        (200, r#"{"2":{"h":5},"10":{"h":5}}"#.to_owned())
    );
    call(
        &mut db,
        "PUT",
        "/k.json?ns=s1",
        r#"{"z":1,"-1":2,"01":3,"1":4,"a":5,".priority":"p"}"#,
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/k.json?ns=s1&orderBy=\"$key\"&startAt=\"1\"&endAt=\"a\"",
            ""
        )
        .1,
        r#"{"1":4,"01":3,"a":5}"#
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/k.json?ns=s1&orderBy=\"$priority\"&startAt=1,\"a\"",
            ""
        )
        .1,
        "{}"
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/k.json?ns=s1&orderBy=\"$key\"&equalTo=\"z\"&limitToLast=1",
            ""
        )
        .1,
        r#"{"z":1}"#
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/k.json?ns=s1&orderBy=\"$priority\"&startAt=true",
            ""
        )
        .1,
        "{}"
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/k.json?ns=s1&orderBy=\"$priority\"&startAt={}",
            ""
        )
        .1,
        r#"{"-1":2,"1":4,"01":3,"a":5,"z":1}"#
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/k.json?ns=s1&orderBy=\"$key\"&startAt=\"b\"&print=pretty",
            ""
        )
        .1,
        "{\n  \"z\" : 1\n}\n"
    );
    assert_eq!(
        call(&mut db, "GET", "/k/a.json?ns=s1&orderBy=\"$key\"", ""),
        (200, "5".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/nothing.json?ns=s1&orderBy=\"$key\"", ""),
        (200, "null".to_owned())
    );
}

#[test]
fn auth_parameters_are_accepted_while_rules_allow_everything() {
    let mut db = query_db();
    for target in [
        "/d/b.json?ns=q1&auth=abc",
        "/d/b.json?ns=q1&access_token=abc",
    ] {
        assert_eq!(
            call(&mut db, "GET", target, ""),
            (200, r#"{"h":1}"#.to_owned())
        );
    }
    let bearer = send(
        &mut db,
        "GET",
        "/d/b.json?ns=q1",
        &[("Authorization", "Bearer abc")],
        "",
    );
    assert_eq!(bearer.status, 200);
}

#[test]
fn deny_all_rules_refuse_everyone_but_the_owner() {
    // Not observed on the official emulator: ledger 1471 Q4 makes productionExact deny
    // everything when no rules are loaded. The refusal shape is production's documented
    // 401 "Permission denied", pending observation.
    let mut db = Database::new(
        RestOptions {
            rules: RulesMode::DenyAll,
            ..RestOptions::default()
        },
        1,
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1", ""),
        (401, error("Permission denied"))
    );
    assert_eq!(
        call(&mut db, "PUT", "/a.json?ns=t1", "1"),
        (401, error("Permission denied"))
    );
    let owner = send(
        &mut db,
        "PUT",
        "/a.json?ns=t1",
        &[("Authorization", "Bearer owner")],
        "1",
    );
    assert_eq!(owner.status, 200);
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&access_token=owner", ""),
        (200, "1".to_owned())
    );
}

#[test]
fn numbers_render_in_java_form() {
    let mut db = db();
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/big.json?ns=s1",
            r#"{"a":-0,"b":100000000000000000000,"c":1.0E-5,"d":0.001,"g":0.1}"#
        )
        .1,
        r#"{"a":0,"b":1.0E20,"c":1.0E-5,"d":0.001,"g":0.1}"#
    );
}

#[test]
fn order_by_accepts_the_root_and_dot_priority() {
    let mut db = query_db();
    // Answers of the official emulator: the root is a child path needing the index "",
    // `.priority` is the priority order, and `.info` is no path.
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"\"", ""),
        (
            400,
            error("Index not defined, add \".indexOn\": \"\", for path \"/d\", to the rules")
        )
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"/\"", ""),
        (
            400,
            error("Index not defined, add \".indexOn\": \"\", for path \"/d\", to the rules")
        )
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/d.json?ns=q1&orderBy=\".priority\"&limitToFirst=2",
            ""
        )
        .1,
        r#"{"2":{"h":5},"10":{"h":5}}"#
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\".info/x\"", ""),
        (400, error("orderBy must be a valid JSON encoded path"))
    );
}

#[test]
fn conditional_requests_cannot_be_silent_or_queries() {
    let mut db = db();
    call(&mut db, "PUT", "/z.json?ns=m1", r#"{"a":1}"#);
    let mixing = error(
        "Mixing 'shallow', querying parameters or 'print=silent' and if-match or if-none-match requests is not supported",
    );
    let tag = "gIphxiFGusLh2VwSNVKSvNu90m4=";
    let silent = send(
        &mut db,
        "DELETE",
        "/z.json?ns=m1&print=silent",
        &[("if-match", tag)],
        "",
    );
    assert_eq!(
        (silent.status, String::from_utf8(silent.body).unwrap()),
        (400, mixing.clone())
    );
    let shallow = send(
        &mut db,
        "GET",
        "/z.json?ns=m1&shallow=true",
        &[("if-none-match", tag)],
        "",
    );
    assert_eq!(
        (shallow.status, String::from_utf8(shallow.body).unwrap()),
        (400, mixing)
    );
}

#[test]
fn if_none_match_answers_not_modified_or_refuses_the_write() {
    let mut db = db();
    call(&mut db, "PUT", "/z.json?ns=m1", r#"{"a":1}"#);
    let tag = "gIphxiFGusLh2VwSNVKSvNu90m4=";
    let unchanged = send(
        &mut db,
        "GET",
        "/z.json?ns=m1",
        &[("if-none-match", tag)],
        "",
    );
    assert_eq!((unchanged.status, unchanged.body.len()), (304, 0));
    let changed = send(
        &mut db,
        "GET",
        "/z.json?ns=m1",
        &[("if-none-match", "other")],
        "",
    );
    assert_eq!((changed.status, header(&changed, "ETag")), (200, Some(tag)));
    assert_eq!(changed.body, br#"{"a":1}"#);
    let refused = send(
        &mut db,
        "PUT",
        "/z.json?ns=m1",
        &[("if-none-match", tag)],
        "2",
    );
    assert_eq!(
        (refused.status, refused.body.as_slice()),
        (412, &br#"{"a":1}"#[..])
    );
    assert_eq!(header(&refused, "ETag"), None);
    let accepted = send(
        &mut db,
        "PUT",
        "/z.json?ns=m1",
        &[("if-none-match", "other")],
        "2",
    );
    assert_eq!(accepted.status, 200);
    assert_eq!(
        call(&mut db, "GET", "/z.json?ns=m1", ""),
        (200, "2".to_owned())
    );
}

#[test]
fn push_ids_increase_across_namespaces() {
    let mut db = db();
    let (_, first) = call(&mut db, "POST", "/l.json?ns=a1", "1");
    let (_, second) = call(&mut db, "POST", "/l.json?ns=b1", "1");
    assert!(first < second, "{first} {second}");
}

#[test]
fn priorities_need_an_existing_node() {
    let mut db = db();
    let missing = error("could not set priority on non-existent node");
    assert_eq!(
        call(&mut db, "PUT", "/missing/.priority.json?ns=u5", "3"),
        (400, missing.clone())
    );
    for body in [
        r#"{"b/.priority":3,"b/c":1}"#,
        r#"{"b/c":1,"b/.priority":3}"#,
    ] {
        assert_eq!(
            call(&mut db, "PATCH", "/.json?ns=u3", body),
            (400, missing.clone()),
            "{body}"
        );
    }
    assert_eq!(
        call(&mut db, "PATCH", "/b.json?ns=u7", r#"{".priority":3}"#),
        (400, missing)
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=u3", ""),
        (200, "null".to_owned())
    );

    call(&mut db, "PUT", "/b.json?ns=u4", r#"{"x":1}"#);
    assert_eq!(
        call(
            &mut db,
            "PATCH",
            "/.json?ns=u4",
            r#"{"b/.priority":3,"b/c":1}"#
        ),
        (200, r#"{"b":{".priority":3,"c":1}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=u4&format=export", "").1,
        r#"{"b":{".priority":3,"c":1,"x":1}}"#
    );
    call(&mut db, "PUT", "/b.json?ns=u6", r#"{"x":1}"#);
    assert_eq!(
        call(
            &mut db,
            "PATCH",
            "/.json?ns=u6",
            r#"{"b/.priority":3,"b/x":null}"#
        ),
        (200, r#"{"b":{".priority":3,"x":null}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=u6", ""),
        (200, "null".to_owned())
    );
    let parse = error("Invalid data; couldn't parse JSON object, array, or value.");
    for body in [
        r#"{".priority":3}"#,
        r#"{"a":null,".priority":1}"#,
        r#"{"a":{".priority":1}}"#,
    ] {
        assert_eq!(
            call(&mut db, "PUT", "/n.json?ns=u8", body),
            (400, parse.clone()),
            "{body}"
        );
    }
}

#[test]
fn priority_placeholders_add_to_the_stored_priority() {
    let mut db = db();
    call(
        &mut db,
        "PUT",
        "/a.json?ns=pri",
        r#"{".value":1,".priority":5}"#,
    );
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/a/.priority.json?ns=pri",
            r#"{".sv":{"increment":1}}"#
        ),
        (200, "6.0".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=pri&format=export", "").1,
        r#"{".value":1,".priority":6.0}"#
    );
}

// Number forms (ledger 1475, Q7 replaced): numbers keep their parsed type and doubles print
// in Java's form, as the official emulator answers.

#[test]
fn numbers_keep_their_type_as_the_official_emulator_answers() {
    let mut db = db();
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/p.json?ns=n1",
            r#"{".value":1,".priority":2}"#
        )
        .1,
        r#"{".value":1,".priority":2.0}"#
    );
    assert_eq!(call(&mut db, "GET", "/p/.priority.json?ns=n1", "").1, "2.0");
    assert_eq!(
        call(&mut db, "PUT", "/a.json?ns=n1", r#"{"a":1.0,"d":-0.0}"#).1,
        r#"{"a":1.0,"d":-0.0}"#
    );
    assert_eq!(
        call(&mut db, "PUT", "/b.json?ns=n1", "[1.5,1e7,1234.5]").1,
        "[1.5,1.0E7,1234.5]"
    );
}

// Round 3 (review 2026-10-19-rtdb-core-r2-rest-review.md); expected answers are the official
// emulator's unless a test says otherwise.

#[test]
fn numbers_beyond_the_double_range_are_stored_as_infinity_strings() {
    let mut db = db();
    let huge = format!("1{}", "0".repeat(400));
    assert_eq!(
        call(&mut db, "PUT", "/big.json?ns=r3", &huge),
        (200, r#""Infinity""#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/big.json?ns=r3", ""),
        (200, r#""Infinity""#.to_owned())
    );
    assert_eq!(
        call(&mut db, "PUT", "/big.json?ns=r3", &format!("-{huge}")),
        (200, r#""-Infinity""#.to_owned())
    );
    assert_eq!(
        call(&mut db, "PUT", "/big.json?ns=r3", "1e400"),
        (200, r#""Infinity""#.to_owned())
    );
    assert_eq!(
        call(&mut db, "PUT", "/big.json?ns=r3", r#"{"a":-1e400}"#),
        (200, r#"{"a":"-Infinity"}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=r3", ""),
        (200, r#"{"big":{"a":"-Infinity"}}"#.to_owned())
    );
}

#[test]
fn download_names_lose_quotes_and_line_breaks() {
    let mut db = db();
    let quoted = send(
        &mut db,
        "GET",
        "/x.json?ns=r3&download=a%22%3B%20x=%22y",
        &[],
        "",
    );
    assert_eq!(
        header(&quoted, "Content-Disposition"),
        Some("attachment; filename=\"a; x=y\"")
    );
    let broken = send(&mut db, "GET", "/x.json?ns=r3&download=a%0d%0ab", &[], "");
    assert_eq!(
        header(&broken, "Content-Disposition"),
        Some("attachment; filename=\"ab\"")
    );
}

#[test]
fn jsonp_answers_are_not_sniffed() {
    // Not observed on the official emulator (it sends no such header); harmless to clients.
    let mut db = db();
    let response = send(&mut db, "GET", "/x.json?ns=r3&callback=cb", &[], "");
    assert_eq!(header(&response, "X-Content-Type-Options"), Some("nosniff"));
}

#[test]
fn if_none_match_is_refused_on_delete_patch_and_post() {
    let mut db = db();
    call(&mut db, "PUT", "/z.json?ns=r5", "1");
    let refused = error(
        "The 'if-none-match' header is not supported with PUT, POST, PATCH or DELETE requests",
    );
    for (method, body) in [("DELETE", ""), ("PATCH", r#"{"a":1}"#), ("POST", "1")] {
        let response = send(
            &mut db,
            method,
            "/z.json?ns=r5",
            &[("if-none-match", "other")],
            body,
        );
        assert_eq!(
            (response.status, String::from_utf8(response.body).unwrap()),
            (400, refused.clone()),
            "{method}"
        );
    }
    assert_eq!(
        call(&mut db, "GET", "/z.json?ns=r5", ""),
        (200, "1".to_owned())
    );
}

#[test]
fn a_priority_path_has_the_priority_leaf_etag() {
    let mut db = db();
    call(
        &mut db,
        "PUT",
        "/pp.json?ns=r3",
        r#"{".value":1,".priority":3}"#,
    );
    let response = send(
        &mut db,
        "GET",
        "/pp/.priority.json?ns=r3",
        &[("X-Firebase-ETag", "true")],
        "",
    );
    assert_eq!(
        header(&response, "ETag"),
        Some("3tYODYzGXwaGnXNech4jb4T9las=")
    );
}

#[test]
fn large_bodies_parse_in_linear_time() {
    // The review measured 1 s for 40 000 keys with the quadratic key positions; 200 000 keys
    // must stay well within a few seconds even in a debug build.
    let mut db = db();
    let body = format!(
        "{{{}}}",
        (0..200_000)
            .map(|i| format!("\"k{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let started = std::time::Instant::now();
    assert_eq!(
        send(
            &mut db,
            "PUT",
            "/many.json?ns=perf",
            &[("print", "silent")],
            &body
        )
        .status,
        200
    );
    let refused = format!("{{\"bad.key\":1,{}}}", &body[1..]);
    let response = send(&mut db, "PUT", "/many.json?ns=perf", &[], &refused);
    assert_eq!(response.status, 400);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn long_bound_parameters_parse_in_linear_time() {
    let mut db = query_db();
    // An unterminated string with many commas: every comma is a candidate split.
    let value = format!("%22{}", "a,".repeat(30_000));
    let started = std::time::Instant::now();
    let (status, _) = call(
        &mut db,
        "GET",
        &format!("/d.json?ns=q1&orderBy=\"$key\"&startAt={value}"),
        "",
    );
    assert_eq!(status, 400);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_priority_on_a_node_the_update_empties_is_dropped() {
    // The official emulator and production (RTDB-REST-20261104-01 emptied-patch) answer 200,
    // the echo in request order, and store nothing.
    let mut db = db();
    call(&mut db, "PUT", "/b.json?ns=u18", r#"{"c":1}"#);
    assert_eq!(
        call(
            &mut db,
            "PATCH",
            "/.json?ns=u18",
            r#"{"b/c":null,"b/.priority":1}"#
        ),
        (200, r#"{"b":{"c":null,".priority":1}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=u18&format=export", ""),
        (200, "null".to_owned())
    );
}

#[test]
fn bodies_are_parsed_before_the_lock_when_there_is_one() {
    use fireemu_adapter_database::rest::parse_body;
    assert!(parse_body(&request("PUT", "/a.json", &[], "1")).is_some());
    assert!(parse_body(&request("PUT", "/a.json", &[], "")).is_none());
    assert!(parse_body(&HttpRequest {
        method: "PUT".to_owned(),
        target: "/a.json".to_owned(),
        headers: Vec::new(),
        body: vec![0xff],
    })
    .is_none());
    // A body parsed beforehand is the one written.
    let mut db = db();
    let put = request("PUT", "/a.json?ns=pb", &[], "5");
    let parsed = parse_body(&put);
    match db.handle_parsed(&put, parsed, NOW) {
        Handled::Response { response, .. } => assert_eq!(response.body, b"5"),
        Handled::Stream { .. } => panic!("no stream expected"),
    }
}

#[test]
fn increments_beyond_the_double_range_stop_at_the_largest_double() {
    // The official emulator answers 1.7976931348623157E308 for 1e308 + 1e308.
    let mut db = Database::new(RestOptions::default(), 1);
    call(&mut db, "PUT", "/i.json?ns=t9", "1e308");
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/i.json?ns=t9",
            r#"{".sv":{"increment":1e308}}"#
        ),
        (200, "1.7976931348623157E308".to_owned())
    );
    call(&mut db, "PUT", "/i.json?ns=t9", "-1e308");
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/i.json?ns=t9",
            r#"{".sv":{"increment":-1e308}}"#
        ),
        (200, "-1.7976931348623157E308".to_owned())
    );
}

#[test]
fn limits_must_be_positive_integers() {
    let mut db = Database::new(RestOptions::default(), 1);
    call(&mut db, "PUT", "/q.json?ns=t10", r#"{"a":1,"b":2,"c":3}"#);
    for (limit, message) in [
        ("2.0", "limitToFirst must be an integer"),
        ("2.5", "limitToFirst must be an integer"),
        ("1e1", "limitToFirst must be an integer"),
        ("-1", "limitToFirst must be positive"),
        ("0", "limitToFirst must be positive"),
    ] {
        assert_eq!(
            call(
                &mut db,
                "GET",
                &format!("/q.json?ns=t10&orderBy=%22%24key%22&limitToFirst={limit}"),
                ""
            ),
            (400, error(message)),
            "{limit}"
        );
    }
}

#[test]
fn a_write_answers_what_was_written_even_when_it_keeps_the_stored_form() {
    // The official emulator answers 1.0 for a PUT of 1.0 over 1, and still reads back 1.
    let mut db = Database::new(RestOptions::default(), 1);
    call(&mut db, "PUT", "/n.json?ns=t11", "1");
    assert_eq!(
        call(&mut db, "PUT", "/n.json?ns=t11", "1.0"),
        (200, "1.0".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/n.json?ns=t11", ""),
        (200, "1".to_owned())
    );
    assert_eq!(
        call(&mut db, "PUT", "/n.json?ns=t11", "-0.0"),
        (200, "-0.0".to_owned())
    );
    assert_eq!(
        call(&mut db, "PUT", "/n.json?ns=t11", "0"),
        (200, "0".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/n.json?ns=t11", ""),
        (200, "-0.0".to_owned())
    );
    call(
        &mut db,
        "PUT",
        "/p.json?ns=t11",
        r#"{".value":1,".priority":5}"#,
    );
    assert_eq!(
        call(&mut db, "PUT", "/p/.priority.json?ns=t11", "5"),
        (200, "5".to_owned())
    );
    // An equal priority keeps the stored double, on a node with children too.
    call(&mut db, "PUT", "/o.json?ns=t11", r#"{"k":1,".priority":5}"#);
    assert_eq!(
        call(&mut db, "PUT", "/o/.priority.json?ns=t11", "5"),
        (200, "5".to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/o/.priority.json?ns=t11", ""),
        (200, "5.0".to_owned())
    );
}

// Native production evidence: RTDB-PRODUCTION-UID-20261024-01, two causal rounds.
// The local owner sentinel replaces the trusted production OAuth credential; it is not
// a claim that production accepts that sentinel or verifies an end-user ID token.
#[test]
fn admin_auth_override_replays_two_native_uid_rounds() {
    let cases = [
        (
            r"alice-put-own",
            r"PUT",
            r"/parity20261023/uidRules/alice.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22alice%22%7D",
            true,
            r#"{"value":1}"#,
            200,
            r#"{"value":1}"#,
        ),
        (
            r"alice-get-own",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22alice%22%7D",
            true,
            r"",
            200,
            r#"{"value":1}"#,
        ),
        (
            r"bob-get-alice",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22bob%22%7D",
            true,
            r"",
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"bob-put-alice-denied",
            r"PUT",
            r"/parity20261023/uidRules/alice.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22bob%22%7D",
            true,
            r#"{"value":999}"#,
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"admin-read-alice-after-bob-denial",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override",
            true,
            r"",
            200,
            r#"{"value":1}"#,
        ),
        (
            r"override-null-get-alice",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override&auth_variable_override=null",
            true,
            r"",
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"override-null-put-alice-denied",
            r"PUT",
            r"/parity20261023/uidRules/alice.json?ns=override&auth_variable_override=null",
            true,
            r#"{"value":999}"#,
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"admin-read-alice-after-null-denial",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override",
            true,
            r"",
            200,
            r#"{"value":1}"#,
        ),
        (
            r"anonymous-get-alice",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override",
            false,
            r"",
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"anonymous-put-alice-denied",
            r"PUT",
            r"/parity20261023/uidRules/alice.json?ns=override",
            false,
            r#"{"value":999}"#,
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"admin-read-alice-after-anonymous-denial",
            r"GET",
            r"/parity20261023/uidRules/alice.json?ns=override",
            true,
            r"",
            200,
            r#"{"value":1}"#,
        ),
        (
            r"bob-put-own",
            r"PUT",
            r"/parity20261023/uidRules/bob.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22bob%22%7D",
            true,
            r#"{"value":2}"#,
            200,
            r#"{"value":2}"#,
        ),
        (
            r"bob-get-own",
            r"GET",
            r"/parity20261023/uidRules/bob.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22bob%22%7D",
            true,
            r"",
            200,
            r#"{"value":2}"#,
        ),
        (
            r"alice-get-bob",
            r"GET",
            r"/parity20261023/uidRules/bob.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22alice%22%7D",
            true,
            r"",
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"alice-put-bob-denied",
            r"PUT",
            r"/parity20261023/uidRules/bob.json?ns=override&auth_variable_override=%7B%22uid%22%3A%22alice%22%7D",
            true,
            r#"{"value":999}"#,
            401,
            r#"{
  "error" : "Permission denied"
}
"#,
        ),
        (
            r"admin-read-bob-after-alice-denial",
            r"GET",
            r"/parity20261023/uidRules/bob.json?ns=override",
            true,
            r"",
            200,
            r#"{"value":2}"#,
        ),
    ];
    for round in 1..=2 {
        let mut db = db();
        db.load_rules("override", r#"{"rules":{".read":false,".write":false,"parity20261023":{"uidRules":{"$uid":{".read":"auth != null && auth.uid === $uid",".write":"auth != null && auth.uid === $uid"}}}}}"#, NOW).unwrap();
        for (id, method, target, admin, body, status, expected) in cases {
            let headers = if admin {
                &[("Authorization", "Bearer owner")][..]
            } else {
                &[]
            };
            let response = send(&mut db, method, target, headers, body);
            assert_eq!(
                (response.status, String::from_utf8(response.body).unwrap()),
                (status, expected.to_owned()),
                "round {round}, {id}"
            );
        }
    }
}

// Local safety policy, not observed malformed/nonadministrator production behavior.
#[test]
fn admin_auth_override_never_inherits_owner_bypass_or_rescues_invalid_credentials() {
    use fireemu_adapter_database::rest::Credentials;
    let mut db = Database::new(
        RestOptions {
            credentials: Credentials {
                strict: true,
                ..Credentials::default()
            },
            ..RestOptions::default()
        },
        1,
    );
    db.load_rules(
        "override",
        r#"{"rules":{".read":false,".write":false}}"#,
        NOW,
    )
    .unwrap();
    for modifier in [
        "null",
        "%7B%22uid%22:%22alice%22%7D",
        "broken",
        "1",
        "true",
        "%5B%5D",
    ] {
        for method in ["GET", "PUT"] {
            let target = format!("/value.json?ns=override&auth_variable_override={modifier}");
            assert_eq!(
                send(
                    &mut db,
                    method,
                    &target,
                    &[("Authorization", "Bearer owner")],
                    "1"
                )
                .status,
                401,
                "{method} {modifier}"
            );
            assert_eq!(
                send(
                    &mut db,
                    method,
                    &target,
                    &[("Authorization", "Bearer invalid")],
                    "1"
                )
                .status,
                401,
                "invalid credential {modifier}"
            );
        }
    }
    assert_eq!(
        send(
            &mut db,
            "GET",
            "/value.json?ns=override",
            &[("Authorization", "Bearer owner")],
            ""
        )
        .status,
        200
    );
}

// Local contract: arbitrary override fields are Rules input, not JWT claims.
#[test]
fn admin_auth_override_access_token_and_arbitrary_claims_are_preserved() {
    let mut db = db();
    db.load_rules("override", r#"{"rules":{".read":"auth.uid == 'charlie' && auth.token.role == 'writer' && auth.extra.enabled == true && auth.provider == 'custom'"}}"#, NOW).unwrap();
    let object = "%7B%22uid%22:%22charlie%22,%22token%22:%7B%22role%22:%22writer%22%7D,%22extra%22:%7B%22enabled%22:true%7D,%22provider%22:%22custom%22%7D";
    let target =
        format!("/value.json?ns=override&access_token=owner&auth_variable_override={object}");
    assert_eq!(call(&mut db, "GET", &target, "").0, 200);
    let anonymous = format!("/value.json?ns=override&auth_variable_override={object}");
    assert_eq!(call(&mut db, "GET", &anonymous, "").0, 401);
}

// SSE is a local adapter regression; the native oracle observed ordinary REST only.
#[test]
fn admin_auth_override_sse_keeps_scoped_context_through_revocation() {
    let mut db = db();
    db.load_rules("override", r#"{"rules":{"value":{".read":"auth.uid == 'alice' && data.child('enabled').val() == true",".write":false}}}"#, NOW).unwrap();
    let owner = &[("Authorization", "Bearer owner")];
    assert_eq!(
        send(
            &mut db,
            "PUT",
            "/value.json?ns=override",
            owner,
            r#"{"enabled":true}"#
        )
        .status,
        200
    );
    let target = "/value.json?ns=override&auth_variable_override=%7B%22uid%22:%22alice%22%7D";
    let stream = db.handle(
        &request(
            "GET",
            target,
            &[
                ("Authorization", "Bearer owner"),
                ("Accept", "text/event-stream"),
            ],
            "",
        ),
        NOW,
    );
    let id = match stream {
        Handled::Stream { id, .. } => id,
        other @ Handled::Response { .. } => panic!("expected scoped stream: {other:?}"),
    };
    let denied = "/value.json?ns=override&auth_variable_override=%7B%22uid%22:%22bob%22%7D";
    assert_eq!(
        send(
            &mut db,
            "GET",
            denied,
            &[
                ("Authorization", "Bearer owner"),
                ("Accept", "text/event-stream")
            ],
            ""
        )
        .status,
        401
    );
    match db.handle(
        &request(
            "PUT",
            "/value.json?ns=override",
            owner,
            r#"{"enabled":false}"#,
        ),
        NOW,
    ) {
        Handled::Response { events, .. } => assert!(events
            .iter()
            .any(|(subscription, event)| *subscription == id && event.is_cancel())),
        other @ Handled::Stream { .. } => panic!("expected write response: {other:?}"),
    }
}

#[test]
fn strict_patch_echo_matches_both_recorded_production_rounds() {
    use fireemu_adapter_database::rest::Credentials;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tools/sdk-smoke-database/fixtures/production-rest.json"
    ))
    .unwrap();
    for round in fixture["rounds"].as_array().unwrap() {
        let expected = round["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "patch-update-nested-and-add")
            .unwrap();
        let mut db = Database::new(
            RestOptions {
                credentials: Credentials {
                    strict: true,
                    ..Credentials::default()
                },
                ..RestOptions::default()
            },
            42,
        );
        call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1,"y":{"z":"s"}}"#);
        let response = send(
            &mut db,
            "PATCH",
            "/a.json?ns=t1",
            &[],
            r#"{"y/z":"t","w":3}"#,
        );
        assert_eq!(
            u64::from(response.status),
            expected["status"].as_u64().unwrap()
        );
        assert_eq!(
            std::str::from_utf8(&response.body).unwrap(),
            expected["bodyText"].as_str().unwrap()
        );
        assert_eq!(header(&response, "ETag"), None);
        assert_eq!(
            call(&mut db, "GET", "/a.json?ns=t1", "").1,
            r#"{"w":3,"x":1,"y":{"z":"t"}}"#
        );
    }
}

#[test]
fn patch_echo_pict_combinations_preserve_the_write_and_output_options() {
    use fireemu_adapter_database::rest::Credentials;
    // Rows generated by work+rtdb-rest-patch-order.pict, including both mandatory seeds.
    for (strict, nested, silent) in [
        (true, true, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
        (false, false, true),
    ] {
        let mut db = Database::new(
            RestOptions {
                credentials: Credentials {
                    strict,
                    ..Credentials::default()
                },
                ..RestOptions::default()
            },
            42,
        );
        let body = if nested {
            r#"{"y/z":"t","w":3}"#
        } else {
            r#"{"y":1,"w":3}"#
        };
        let suffix = if silent { "&print=silent" } else { "" };
        let response = send(
            &mut db,
            "PATCH",
            &format!("/a.json?ns=t1{suffix}"),
            &[],
            body,
        );
        if silent {
            assert_eq!((response.status, response.body.as_slice()), (204, &[][..]));
        } else {
            let expected = if nested {
                r#"{"y":{"z":"t"},"w":3}"#
            } else {
                r#"{"y":1,"w":3}"#
            };
            assert_eq!(
                (
                    response.status,
                    std::str::from_utf8(&response.body).unwrap()
                ),
                (200, expected)
            );
        }
        let expected = if nested {
            r#"{"w":3,"y":{"z":"t"}}"#
        } else {
            r#"{"w":3,"y":1}"#
        };
        assert_eq!(call(&mut db, "GET", "/a.json?ns=t1", "").1, expected);
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn strict_patch_echo_preserves_root_entry_permutation(n in 0_u32..1000, reverse in proptest::bool::ANY) {
        use fireemu_adapter_database::rest::Credentials;
        let mut db = Database::new(RestOptions {
            credentials: Credentials { strict: true, ..Credentials::default() },
            ..RestOptions::default()
        }, 42);
        let (first, second) = if reverse { (format!("a{n}"), format!("z{n}")) } else { (format!("z{n}"), format!("a{n}")) };
        let body = format!(r#"{{"{first}":1,"{second}":2}}"#);
        let response = call(&mut db, "PATCH", "/a.json?ns=t1", &body);
        proptest::prop_assert_eq!(response, (200, body));
    }
}

#[test]
fn strict_patch_echo_keeps_normalized_shared_roots_and_resolves_values() {
    use fireemu_adapter_database::rest::Credentials;
    let mut db = Database::new(
        RestOptions {
            credentials: Credentials {
                strict: true,
                ..Credentials::default()
            },
            ..RestOptions::default()
        },
        42,
    );
    let response = call(
        &mut db,
        "PATCH",
        "/a.json?ns=t1",
        r#"{"z//a":{".sv":"timestamp"},"z/b":2,"a":3}"#,
    );
    assert_eq!(
        response,
        (200, format!(r#"{{"z":{{"a":{NOW},"b":2}},"a":3}}"#))
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1", "").1,
        format!(r#"{{"a":3,"z":{{"a":{NOW},"b":2}}}}"#)
    );
}

#[test]
fn recorded_next4_patch_echo_matches_both_profiles_and_rounds() {
    use fireemu_adapter_database::rest::Credentials;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tools/sdk-smoke-database/fixtures/production-rest-next4.json"
    ))
    .unwrap();
    for strict in [true, false] {
        for round in fixture["rounds"].as_array().unwrap() {
            let expected = round["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == "patch-anchor")
                .unwrap();
            assert_eq!(expected["bodyBase64"], "eyJ5Ijp7InoiOiJ0In0sInciOjN9");
            let mut db = Database::new(
                RestOptions {
                    credentials: Credentials {
                        strict,
                        ..Credentials::default()
                    },
                    ..RestOptions::default()
                },
                42,
            );
            assert_eq!(
                call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1,"y":{"z":"s"}}"#).0,
                200
            );
            let response = send(
                &mut db,
                "PATCH",
                "/a.json?ns=t1",
                &[],
                r#"{"y/z":"t","w":3}"#,
            );
            assert_eq!(
                u64::from(response.status),
                expected["status"].as_u64().unwrap()
            );
            assert_eq!(response.body, br#"{"y":{"z":"t"},"w":3}"#);
            assert_eq!(header(&response, "ETag"), None);
            assert_eq!(
                call(&mut db, "GET", "/a.json?ns=t1", "").1,
                r#"{"w":3,"x":1,"y":{"z":"t"}}"#
            );
        }
    }
}

#[test]
fn patch_profile_generated_cases_preserve_output_guards_and_storage() {
    use fireemu_adapter_database::rest::Credentials;
    for line in include_str!("patch-profile.generated.tsv").lines().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 3, "{line}");
        let strict = columns[0] == "strict";
        let mut db = Database::new(
            RestOptions {
                credentials: Credentials {
                    strict,
                    ..Credentials::default()
                },
                ..RestOptions::default()
            },
            42,
        );
        let (body, expected, stored) = match columns[1] {
            "nested" => (
                r#"{"y/z":"t","w":3}"#,
                r#"{"y":{"z":"t"},"w":3}"#,
                r#"{"w":3,"y":{"z":"t"}}"#,
            ),
            "simple" => (r#"{"y":1,"w":3}"#, r#"{"y":1,"w":3}"#, r#"{"w":3,"y":1}"#),
            "conflict" => (r#"{"x":1,"x/y":2}"#, "", "null"),
            _ => panic!("unknown input {line}"),
        };
        let option = match columns[2] {
            "compact" => "",
            "pretty" => "&print=pretty",
            "silent" => "&print=silent",
            "callback" => "&callback=cb",
            _ => panic!("unknown output {line}"),
        };
        let response = send(
            &mut db,
            "PATCH",
            &format!("/a.json?ns=t1{option}"),
            &[("X-Firebase-ETag", "true")],
            body,
        );
        if columns[1] == "conflict" {
            assert_eq!(response.status, 400, "{line}");
        } else if columns[2] == "silent" {
            assert_eq!(
                (response.status, response.body.as_slice()),
                (204, &[][..]),
                "{line}"
            );
        } else {
            assert_eq!(response.status, 200, "{line}");
            let text = std::str::from_utf8(&response.body).unwrap();
            if columns[2] == "compact" {
                assert_eq!(text, expected, "{line}");
            }
            let json = if columns[2] == "callback" {
                text.strip_prefix("/**/ cb(")
                    .unwrap()
                    .strip_suffix(");")
                    .unwrap()
            } else {
                text
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(json).unwrap(),
                serde_json::from_str::<serde_json::Value>(expected).unwrap(),
                "{line}"
            );
        }
        assert_eq!(header(&response, "ETag"), None, "{line}");
        assert_eq!(
            call(&mut db, "GET", "/a.json?ns=t1", "").1,
            stored,
            "{line}"
        );
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn ordinary_patch_echo_preserves_root_entry_permutation(n in 0_u32..1000, reverse in proptest::bool::ANY) {
        let mut db = db();
        let (first, second) = if reverse { (format!("a{n}"), format!("z{n}")) } else { (format!("z{n}"), format!("a{n}")) };
        let body = format!(r#"{{"{first}":1,"{second}":2}}"#);
        proptest::prop_assert_eq!(call(&mut db, "PATCH", "/a.json?ns=t1", &body), (200, body));
    }
}

#[test]
fn ordinary_patch_echo_keeps_shared_roots_and_resolves_values() {
    let mut db = db();
    let response = call(
        &mut db,
        "PATCH",
        "/a.json?ns=t1",
        r#"{"z//a":{".sv":"timestamp"},"z/b":2,"a":3}"#,
    );
    assert_eq!(
        response,
        (200, format!(r#"{{"z":{{"a":{NOW},"b":2}},"a":3}}"#))
    );
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1", "").1,
        format!(r#"{{"a":3,"z":{{"a":{NOW},"b":2}}}}"#)
    );
}

// ---- Credential answers recorded by the G10 production run (RTDB-TOKENS-20261104-01) ----
//
// The oracle below states, for every combination of profile, carrier, token, path and mode, what
// the answer was before the G10 findings (everything outside the recorded shape) and what the
// recording says (the recorded shape: a GET that is not an event stream, on a data path). Row ids
// name the cases of the recording (tools/sdk-smoke-database/fixtures/production-sdk-tokens.json).

#[allow(
    clippy::format_push_string,
    clippy::match_same_arms,
    clippy::semicolon_if_nothing_returned
)] // an oracle written as a table
mod g10 {
    use super::*;
    use fireemu_adapter_database::rest::Credentials;
    use std::sync::Arc;

    const VALID_USER: &str = "valid.user.token";
    const OPAQUE: &str = "5f3c9a1b2d4e6f708192a3b4c5d6e7f801234567";
    const NONE: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1IiwiaWF0IjoxfQ.";
    const RS256: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1IiwiaWF0IjoxfQ.c2ln";
    const HS256: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1IiwiaWF0IjoxfQ.c2ln";
    const PERMISSION_DENIED: &str = "{\n  \"error\" : \"Permission denied\"\n}\n";
    const UNAUTHORIZED: &str = "{\n  \"error\" : \"Unauthorized request.\"\n}\n";

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Carrier {
        Auth,
        Bearer,
        AccessToken,
        Nothing,
    }

    fn tokens() -> Vec<(&'static str, String)> {
        vec![
            ("absent", String::new()),
            ("empty", String::new()),
            ("opaque", OPAQUE.to_owned()),
            ("owner", "owner".to_owned()),
            ("null", "null".to_owned()),
            ("jwt_none", NONE.to_owned()),
            ("jwt_rs256", RS256.to_owned()),
            ("jwt_hs256", HS256.to_owned()),
            ("two_seg", "aaa.bbb".to_owned()),
            ("huge", "a".repeat(5000)),
            ("pct", "a b+c/d=e%f&g#h?i\"j".to_owned()),
            ("adc", "ya29.A0Test-token_abc".to_owned()),
            ("user", VALID_USER.to_owned()),
        ]
    }

    fn encode(text: &str) -> String {
        text.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    fn database(strict: bool) -> Database {
        let verifier: fireemu_adapter_database::rest::IdTokenVerifier = Arc::new(|token, _, _| {
            (token == VALID_USER).then(|| r#"{"sub":"u1","iat":1}"#.to_owned())
        });
        let mut db = Database::new(
            RestOptions {
                credentials: Credentials {
                    strict,
                    id_tokens: Some(verifier),
                },
                ..RestOptions::default()
            },
            1,
        );
        db.load_rules(
            "g10",
            r#"{"rules":{".read":false,".write":false,"pub":{".read":true,".write":true},"authreq":{".read":"auth != null"}}}"#,
            NOW,
        )
        .unwrap();
        // The seed is written by the administrator, as the suite does.
        for (path, value) in [("pub", r#"{"v":1}"#), ("authreq", r#"{"v":3}"#)] {
            let response = send(
                &mut db,
                "PUT",
                &format!("/{path}.json?ns=g10"),
                &[("Authorization", "Bearer owner")],
                value,
            );
            assert_eq!(response.status, 200, "seed {path}");
        }
        db
    }

    /// The answer of a request: (status, body).
    fn run(
        db: &mut Database,
        carrier: Carrier,
        token: &str,
        path: &str,
        mode: &str,
    ) -> Option<(u16, String)> {
        let (method, accept): (&str, &[(&str, &str)]) = match mode {
            "get" => ("GET", &[]),
            "stream" => ("GET", &[("Accept", "text/event-stream")]),
            _ => ("PUT", &[]),
        };
        let mut query = "ns=g10".to_owned();
        let mut headers: Vec<(&str, String)> =
            accept.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        match carrier {
            Carrier::Auth => query.push_str(&format!("&auth={}", encode(token))),
            Carrier::AccessToken => query.push_str(&format!("&access_token={}", encode(token))),
            Carrier::Bearer => headers.push(("Authorization", format!("Bearer {token}"))),
            Carrier::Nothing => {}
        }
        let target = format!(
            "/{}.json?{query}",
            if path == "settings" {
                ".settings/rules"
            } else {
                path
            }
        );
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = match (method, path) {
            ("PUT", "pub") => r#"{"v":1}"#,
            ("PUT", _) => r#"{"v":3}"#,
            _ => "",
        };
        let response = match db.handle(&request(method, &target, &borrowed, body), NOW) {
            Handled::Response { response, .. } => response,
            Handled::Stream { .. } => return None,
        };
        Some((response.status, String::from_utf8(response.body).unwrap()))
    }

    /// Who the credential makes the request, before and after the findings: `None` is a refusal.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Who {
        Owner,
        Admin,
        User,
        Anonymous,
        Refused,
    }

    fn who(strict: bool, carrier: Carrier, name: &str, token: &str) -> Who {
        match carrier {
            Carrier::Nothing => Who::Anonymous,
            Carrier::Bearer | Carrier::AccessToken if token == "owner" => Who::Owner,
            Carrier::Bearer | Carrier::AccessToken => {
                if strict {
                    Who::Refused
                } else {
                    Who::Admin
                }
            }
            Carrier::Auth if name == "user" => Who::User,
            Carrier::Auth if strict => Who::Refused,
            Carrier::Auth => Who::Anonymous,
        }
    }

    fn answer_for(who: Who, path: &str, mode: &str) -> (u16, String) {
        let administrator = matches!(who, Who::Owner | Who::Admin);
        // An event stream is read like a GET: it opens where a GET would answer 2xx.
        let mode = if mode == "stream" { "get" } else { mode };
        match (who, path, mode) {
            (Who::Refused, _, _) => (401, PERMISSION_DENIED.to_owned()),
            (_, "settings", _) if administrator => (200, String::new()),
            (_, "settings", _) => (403, error("Permission denied.")),
            (_, "pub", _) => (200, r#"{"v":1}"#.to_owned()),
            (Who::Anonymous, "authreq", "get") => (401, PERMISSION_DENIED.to_owned()),
            (_, "authreq", "get") => (200, r#"{"v":3}"#.to_owned()),
            (_, "authreq", _) if administrator => (200, r#"{"v":3}"#.to_owned()),
            _ => (401, PERMISSION_DENIED.to_owned()),
        }
    }

    fn comparable(path: &str, answer: (u16, String)) -> (u16, String) {
        if path == "settings" && answer.0 == 200 {
            (200, String::new())
        } else {
            answer
        }
    }

    /// What the recording says, where it says anything.
    fn recorded(
        strict: bool,
        carrier: Carrier,
        name: &str,
        token: &str,
        path: &str,
        mode: &str,
    ) -> Option<(u16, String)> {
        let data_read = mode == "get" && path != "settings";
        if !strict || !data_read {
            return None;
        }
        match carrier {
            // auth-random-pub (200 {"v":1}) and auth-random on authreq (401 Permission denied).
            Carrier::Auth if name == "opaque" => Some(answer_for(Who::Anonymous, path, mode)),
            // bearer-random(-pub), bearer-none-own, bearer-rs256, bearer-null: not bearer-empty.
            Carrier::Bearer if !token.is_empty() && token != "owner" => {
                Some((401, UNAUTHORIZED.to_owned()))
            }
            // at-empty, at-random(-pub), at-rs256: every access_token but the owner's.
            Carrier::AccessToken if token != "owner" => Some((401, UNAUTHORIZED.to_owned())),
            _ => None,
        }
    }

    /// The rows of the recording this change reproduces, by the case id of the tokens suite
    /// (strict profile; every row is a GET of `/pub.json` or `/authreq.json`).
    #[test]
    fn strict_reproduces_the_recorded_g10_rows() {
        let mut db = database(true);
        let long = "a".repeat(5000);
        let rows: Vec<(&str, Carrier, &str, &str, u16, &str)> = vec![
            (
                "auth-random-pub",
                Carrier::Auth,
                OPAQUE,
                "pub",
                200,
                r#"{"v":1}"#,
            ),
            (
                "auth-random",
                Carrier::Auth,
                OPAQUE,
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-empty",
                Carrier::Auth,
                "",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-none-own",
                Carrier::Auth,
                NONE,
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-rs256",
                Carrier::Auth,
                RS256,
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-hs256",
                Carrier::Auth,
                HS256,
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-two-seg",
                Carrier::Auth,
                "aaa.bbb",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-huge",
                Carrier::Auth,
                &long,
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-pct",
                Carrier::Auth,
                "a b+c/d=e%f&g#h?i\"j",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-null",
                Carrier::Auth,
                "null",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "auth-adc",
                Carrier::Auth,
                "ya29.A0Test-token_abc",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "bearer-empty",
                Carrier::Bearer,
                "",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "bearer-random",
                Carrier::Bearer,
                OPAQUE,
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "bearer-none-own",
                Carrier::Bearer,
                NONE,
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "bearer-rs256",
                Carrier::Bearer,
                RS256,
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "bearer-null",
                Carrier::Bearer,
                "null",
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "bearer-random-pub",
                Carrier::Bearer,
                OPAQUE,
                "pub",
                401,
                UNAUTHORIZED,
            ),
            (
                "at-empty",
                Carrier::AccessToken,
                "",
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "at-random",
                Carrier::AccessToken,
                OPAQUE,
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "at-rs256",
                Carrier::AccessToken,
                RS256,
                "authreq",
                401,
                UNAUTHORIZED,
            ),
            (
                "at-random-pub",
                Carrier::AccessToken,
                OPAQUE,
                "pub",
                401,
                UNAUTHORIZED,
            ),
            (
                "ctl-anon-authreq",
                Carrier::Nothing,
                "",
                "authreq",
                401,
                PERMISSION_DENIED,
            ),
            (
                "ctl-anon-pub",
                Carrier::Nothing,
                "",
                "pub",
                200,
                r#"{"v":1}"#,
            ),
            (
                "ctl-admin-authreq",
                Carrier::Bearer,
                "owner",
                "authreq",
                200,
                r#"{"v":3}"#,
            ),
        ];
        for (id, carrier, token, path, status, body) in rows {
            let answer = run(&mut db, carrier, token, path, "get").expect("a response");
            assert_eq!(answer, (status, body.to_owned()), "{id}");
        }
    }

    /// `auth` is judged by its decoded value, as production reads the query, and an event stream
    /// in any spelling of the media type keeps its old answers.
    #[test]
    fn the_decoded_auth_value_and_any_spelling_of_an_event_stream() {
        let mut db = database(true);
        let read = |db: &mut Database, query: &str, headers: &[(&str, &str)]| {
            let response = send(db, "GET", &format!("/pub.json?ns=g10{query}"), headers, "");
            (response.status, String::from_utf8(response.body).unwrap())
        };
        let nobody = (200, r#"{"v":1}"#.to_owned());
        let refused = (401, PERMISSION_DENIED.to_owned());
        // `%61` is `a`; `%61uth=a` names the `auth` parameter.
        assert_eq!(read(&mut db, "&auth=%61", &[]), nobody);
        assert_eq!(read(&mut db, "&%61uth=a", &[]), nobody);
        assert_eq!(read(&mut db, "&auth=a%62%63", &[]), nobody);
        // A decoded value outside the opaque shape stays refused.
        assert_eq!(read(&mut db, "&auth=a%2Eb", &[]), refused);
        assert_eq!(read(&mut db, "&auth=%20", &[]), refused);
        // Mixed-case media types are event streams too: the old answers, not the G10 ones.
        for accept in [
            "Text/Event-Stream",
            "TEXT/EVENT-STREAM",
            "application/json, Text/Event-Stream",
        ] {
            assert_eq!(
                read(&mut db, &format!("&auth={OPAQUE}"), &[("Accept", accept)]),
                refused,
                "{accept}"
            );
            assert_eq!(
                read(
                    &mut db,
                    "",
                    &[("Accept", accept), ("Authorization", "Bearer random")]
                ),
                refused,
                "{accept}"
            );
            assert_eq!(
                read(&mut db, "&access_token=x", &[("Accept", accept)]),
                refused,
                "{accept}"
            );
        }
        // Without the event-stream type the G10 answers apply.
        assert_eq!(
            read(
                &mut db,
                &format!("&auth={OPAQUE}"),
                &[("Accept", "application/json")]
            ),
            nobody
        );
    }

    #[test]
    fn credential_answers_follow_the_recording_where_it_speaks_and_the_old_answers_elsewhere() {
        let mut moved = Vec::new();
        for strict in [true, false] {
            let mut db = database(strict);
            for carrier in [
                Carrier::Auth,
                Carrier::Bearer,
                Carrier::AccessToken,
                Carrier::Nothing,
            ] {
                for (name, token) in tokens() {
                    if (carrier == Carrier::Nothing) != (name == "absent")
                        || (name == "user" && carrier != Carrier::Auth)
                    {
                        continue;
                    }
                    if name == "adc" && carrier == Carrier::Bearer {
                        continue;
                    }
                    for path in ["pub", "authreq", "settings"] {
                        for mode in ["get", "stream", "put"] {
                            if path == "settings" && mode != "get" {
                                continue;
                            }
                            let outcome = run(&mut db, carrier, &token, path, mode);
                            let old = comparable(
                                path,
                                answer_for(who(strict, carrier, name, &token), path, mode),
                            );
                            if mode == "stream" {
                                // A stream opens exactly where a read would answer 200 and is
                                // refused in plain text otherwise; no recorded row covers it.
                                match outcome {
                                    None => assert_eq!(
                                        old.0, 200,
                                        "strict={strict} {carrier:?} {name} {path}: opened a stream"
                                    ),
                                    Some(refused) => assert_eq!(
                                        (old.0, refused),
                                        (401, (401, "Permission denied".to_owned())),
                                        "strict={strict} {carrier:?} {name} {path}: stream"
                                    ),
                                }
                                continue;
                            }
                            let actual = outcome.expect("a response, not a stream");
                            let expected = recorded(strict, carrier, name, &token, path, mode)
                                .unwrap_or_else(|| old.clone());
                            let actual = comparable(path, actual);
                            assert_eq!(
                                actual, expected,
                                "strict={strict} {carrier:?} {name} {path} {mode}"
                            );
                            if expected != old {
                                moved.push((carrier, name, path, mode, old.0, expected.0));
                            }
                        }
                    }
                }
            }
        }
        // Everything that moved: only strict, only GET, and none to an identity: the answers that
        // changed are 401 -> 401 with another body (S2) or 401 -> the anonymous answer (S1).
        assert_ne!(moved, [] as [(g10::Carrier, &str, &str, &str, u16, u16); 0]);
        for (carrier, name, _, mode, before, after) in &moved {
            assert_eq!(*mode, "get");
            match carrier {
                Carrier::Auth => {
                    assert!(*name == "opaque" && *before == 401 && (*after == 200 || *after == 401))
                }
                Carrier::Bearer | Carrier::AccessToken => assert!(*before == 401 && *after == 401),
                Carrier::Nothing => panic!("an absent credential moved"),
            }
        }
    }
}

/// A lone surrogate escape in a JSON string value is `?` on the emulator profile, one for each lone unit and a
/// pair untouched, as the official emulator stores it (owner 2276; jar rows in
/// `docs.local/runs/rtdb-lone-surrogate/jar-json1.json` and `jar-json2.json`). A key holding one is refused
/// in both profiles. The strict profile refuses every value that holds one, as it did: production has not answered.
#[test]
fn a_lone_surrogate_in_a_body_value_is_a_question_mark_on_the_emulator_profile_only() {
    let parse = error("Invalid data; couldn't parse JSON object, array, or value.");
    // (method, path, seed, body, the emulator profile's answer, the strict profile's status)
    type Row<'a> = (&'a str, &'a str, &'a str, &'a str, (u16, String), u16);
    let rows: Vec<Row<'_>> = vec![
        (
            "PUT",
            "/t",
            "",
            r#""a\ud83d""#,
            (200, r#""a?""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#""\ud83d\ud83d""#,
            (200, r#""??""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#""\ude00""#,
            (200, r#""?""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#""\ud83dx""#,
            (200, r#""?x""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#""\ud83dA""#,
            (200, r#""?A""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#""\ude00\ud83d""#,
            (200, r#""??""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#""😀""#,
            (200, "\"\u{1F600}\"".to_owned()),
            200,
        ),
        (
            "PUT",
            "/t",
            "",
            r#"{"a":"x\ud83d"}"#,
            (200, r#"{"a":"x?"}"#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#"{".value":"x\ud83d"}"#,
            (200, r#""x?""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#"{".value":1,".priority":"p\ud83d"}"#,
            (200, r#"{".value":1,".priority":"p?"}"#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t/.priority",
            "1",
            r#""p\ud83d""#,
            (200, r#""p?""#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#"{"a":["x\ud83d"]}"#,
            (200, r#"{"a":["x?"]}"#.to_owned()),
            400,
        ),
        (
            "PUT",
            "/t",
            "",
            r#"["x\ud83d"]"#,
            (200, r#"["x?"]"#.to_owned()),
            400,
        ),
        (
            "PATCH",
            "/t",
            r#"{"a":1}"#,
            r#"{"a/b":"x\ud83d","c":1}"#,
            (200, r#"{"a":{"b":"x?"},"c":1}"#.to_owned()),
            400,
        ),
        (
            "PATCH",
            "/t",
            r#"{"a":1}"#,
            r#"{".priority":"q\ud83d"}"#,
            (200, r#"{".priority":"q?"}"#.to_owned()),
            400,
        ),
        // A key holding a lone surrogate is refused on both profiles.
        (
            "PUT",
            "/t",
            "",
            r#"{"a\ud83d":1}"#,
            (400, parse.clone()),
            400,
        ),
    ];
    for strict in [false, true] {
        for (method, path, seed, body, emulator, strict_status) in &rows {
            let options = RestOptions {
                production_shapes: strict,
                ..RestOptions::default()
            };
            let mut db = Database::new(options, 42);
            if !seed.is_empty() {
                assert_eq!(call(&mut db, "PUT", "/t.json?ns=t1", seed).0, 200);
            }
            let got = call(&mut db, method, &format!("{path}.json?ns=t1"), body);
            if strict {
                assert_eq!(got.0, *strict_status, "strict {method} {path} {body}");
                if *strict_status == 400 {
                    assert_eq!(got.1, parse, "strict {method} {path} {body}");
                }
            } else {
                assert_eq!(&got, emulator, "{method} {path} {body}");
            }
        }
    }
    // POST stores the value the same way.
    let mut db = db();
    let (status, answer) = call(&mut db, "POST", "/t.json?ns=t1", r#""x\ud83d""#);
    assert_eq!(status, 200, "{answer}");
    let (status, answer) = call(&mut db, "GET", "/t.json?ns=t1", "");
    assert_eq!(status, 200);
    assert!(answer.ends_with(r#":"x?"}"#), "{answer}");
}
