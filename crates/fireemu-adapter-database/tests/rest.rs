//! The REST API, request by request. Unless a test says otherwise, every expected status,
//! header and body is what the official emulator (firebase-database-emulator v4.11.2) answered
//! to the same request.

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

fn send(db: &mut Database, method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> HttpResponse {
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
    format!("{{\n  \"error\" : \"{}\"\n}}", message.replace('"', "\\\""))
}

#[test]
fn put_get_patch_delete_round_trip() {
    let mut db = db();
    assert_eq!(
        call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1,"y":{"z":"s"}}"#),
        (200, r#"{"x":1,"y":{"z":"s"}}"#.to_owned())
    );
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1", ""), (200, r#"{"x":1,"y":{"z":"s"}}"#.to_owned()));
    assert_eq!(
        call(&mut db, "PATCH", "/a.json?ns=t1", r#"{"y/z":"t","w":3}"#),
        (200, r#"{"w":3,"y":{"z":"t"}}"#.to_owned())
    );
    assert_eq!(call(&mut db, "DELETE", "/a/y.json?ns=t1", ""), (200, "null".to_owned()));
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1", ""), (200, r#"{"w":3,"x":1}"#.to_owned()));
    assert_eq!(call(&mut db, "GET", "/missing.json?ns=t1", ""), (200, "null".to_owned()));
}

#[test]
fn json_answers_carry_the_server_headers() {
    let mut db = db();
    let response = send(&mut db, "GET", "/a.json?ns=t1", &[], "");
    assert_eq!(header(&response, "Content-Type"), Some("application/json; charset=utf-8"));
    assert_eq!(header(&response, "Access-Control-Allow-Origin"), Some("*"));
    assert_eq!(header(&response, "Cache-Control"), Some("no-cache"));
    assert_eq!(header(&response, "ETag"), None);
}

#[test]
fn namespaces_are_isolated() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=one", "1");
    assert_eq!(call(&mut db, "GET", "/a.json?ns=two", ""), (200, "null".to_owned()));
    assert_eq!(call(&mut db, "GET", "/a.json?ns=one", ""), (200, "1".to_owned()));
    assert_eq!(db.tree("one").unwrap().get(&Path::root()).is_some(), true);
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
    assert_eq!(get(&[host("q1.europe-west1.firebasedatabase.app")], "/a.json"), "1");
    assert_eq!(get(&[host("q1.localhost:9000")], "/a.json"), "1");
    assert_eq!(get(&[host("Q1.firebaseio.com")], "/a.json"), "1");
    assert_eq!(get(&[host("other.firebaseio.com")], "/a.json?ns=q1"), "1");
    assert_eq!(get(&[host("localhost:9000")], "/a.json"), "null");
    assert_eq!(get(&[host("127.0.0.1:9000")], "/a.json"), "null");
    assert_eq!(get(&[], "/a.json?ns=Q1"), "1");
    call(&mut db, "PUT", "/d.json", "2");
    assert_eq!(call(&mut db, "GET", "/d.json?ns=fake-server", ""), (200, "2".to_owned()));
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
    for ns in ["a-b", "1abc", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop"] {
        assert_eq!(call(&mut db, "GET", &format!("/x.json?ns={ns}"), "").0, 200, "{ns:?}");
    }
}

#[test]
fn urls_must_end_in_dot_json() {
    let mut db = db();
    let response = send(&mut db, "GET", "/d/a?ns=q1", &[], "");
    assert_eq!(response.status, 400);
    assert_eq!(header(&response, "Content-Type"), Some("text/plain"));
    assert_eq!(response.body, b"Append .json to your URL to use the REST API.");
}

#[test]
fn invalid_paths_are_refused() {
    let mut db = db();
    let token = error("Invalid path: Invalid token in path");
    assert_eq!(call(&mut db, "PUT", "/b$ad.json?ns=t1", "1"), (400, token.clone()));
    assert_eq!(call(&mut db, "PUT", "/.info/x.json?ns=t1", "1"), (400, token.clone()));
    assert_eq!(call(&mut db, "GET", "/.info.json?ns=t1", ""), (400, token.clone()));
    assert_eq!(call(&mut db, "PUT", "/x/.priority/y.json?ns=t1", "5"), (400, token));
    let deep = (0..33).map(|i| format!("k{i}")).collect::<Vec<_>>().join("/");
    assert_eq!(
        call(&mut db, "PUT", &format!("/{deep}.json?ns=v1"), "1"),
        (400, error("Invalid path: Path specified exceeds the maximum depth that can be written (32)."))
    );
    let shallow = (0..32).map(|i| format!("k{i}")).collect::<Vec<_>>().join("/");
    assert_eq!(call(&mut db, "PUT", &format!("/{shallow}.json?ns=v1"), "1").0, 200);
    assert_eq!(
        call(&mut db, "PUT", &format!("/{}.json?ns=v1", "a".repeat(769)), "1"),
        (400, error("Invalid path: Path specified exceeds the maximum length that can be written (768 bytes)."))
    );
}

#[test]
fn percent_encoded_paths_are_decoded() {
    let mut db = db();
    assert_eq!(call(&mut db, "PUT", "/a%20b.json?ns=v1", "1").0, 200);
    assert_eq!(call(&mut db, "GET", "/.json?ns=v1", ""), (200, r#"{"a b":1}"#.to_owned()));
    // An encoded slash separates keys like a plain one.
    assert_eq!(call(&mut db, "PUT", "/a%2Fb.json?ns=v2", "1").0, 200);
    assert_eq!(call(&mut db, "GET", "/a.json?ns=v2", ""), (200, r#"{"b":1}"#.to_owned()));
}

#[test]
fn settings_are_permission_denied_until_rules_are_served() {
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
    assert_eq!(call(&mut db, "PUT", "/bad.json?ns=t1", r#"{"a.b":1}"#), (400, key("1:2")));
    assert_eq!(call(&mut db, "PUT", "/bad.json?ns=t1", "{bad json"), (400, parse.clone()));
    assert_eq!(call(&mut db, "PUT", "/bad.json?ns=t1", ""), (400, error("No data supplied.")));
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=v1", r#"{"a":{"b":{"c.d":1}}}"#), (400, key("1:12")));
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=v1", "{\n  \"a\" : {\"b$\":1}}"), (400, key("2:10")));
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=v1", r#"{".other":1}"#), (400, key("1:2")));
    assert_eq!(call(&mut db, "PUT", "/f.json?ns=q1", r#"{"x":{"y":1},"x/z":2}"#), (400, key("1:14")));
    for body in [
        r#"{"":1}"#,
        r#"{"a":1,".priority":true}"#,
        r#"{".value":1,"a":2}"#,
        r#"{".sv":"timestamp","x":1}"#,
        r#"{".sv":{"increment":"1"}}"#,
        r#"{".sv":"nope"}"#,
    ] {
        assert_eq!(call(&mut db, "PUT", "/x.json?ns=v1", body), (400, parse.clone()), "{body}");
    }
    let shallow = (0..32).map(|i| format!("k{i}")).collect::<Vec<_>>().join("/");
    assert_eq!(call(&mut db, "PUT", &format!("/{shallow}.json?ns=v1"), r#"{"a":1}"#), (400, parse.clone()));
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=v1", &format!(r#"{{"{}":1}}"#, "a".repeat(768))),
        (400, parse)
    );
    assert_eq!(call(&mut db, "GET", "/.json?ns=v1", ""), (200, "null".to_owned()));
}

#[test]
fn put_answers_the_stored_value_in_export_form() {
    let mut db = db();
    assert_eq!(
        call(&mut db, "PUT", "/p.json?ns=t1", r#"{".value":1,".priority":2}"#),
        (200, r#"{".value":1,".priority":2}"#.to_owned())
    );
    assert_eq!(call(&mut db, "GET", "/p.json?ns=t1", ""), (200, "1".to_owned()));
    assert_eq!(call(&mut db, "GET", "/p.json?ns=t1&format=export", ""), (200, r#"{".value":1,".priority":2}"#.to_owned()));
    assert_eq!(call(&mut db, "GET", "/p/.priority.json?ns=t1", ""), (200, "2".to_owned()));
    assert_eq!(call(&mut db, "PUT", "/arr.json?ns=t1", r#"["a","b",null,"d"]"#), (200, r#"["a","b",null,"d"]"#.to_owned()));
    assert_eq!(call(&mut db, "PUT", "/x/.priority.json?ns=t1", "5"), (200, "5".to_owned()));
    assert_eq!(
        call(&mut db, "PUT", "/x/.priority.json?ns=t1", "true"),
        (400, error("Invalid data; couldn't parse JSON object, array, or value."))
    );
}

#[test]
fn server_values_resolve_at_the_request_time() {
    let mut db = db();
    assert_eq!(call(&mut db, "PUT", "/ts.json?ns=t1", r#"{".sv":"timestamp"}"#), (200, NOW.to_string()));
    assert_eq!(
        call(&mut db, "PUT", "/ts.json?ns=t1", r#"{".sv":{"increment":2}}"#),
        (200, (NOW + 2).to_string())
    );
    assert_eq!(
        call(&mut db, "PATCH", "/x.json?ns=v1", r#"{"t":{".sv":"timestamp"}}"#),
        (200, format!(r#"{{"t":{NOW}}}"#))
    );
}

#[test]
fn post_creates_increasing_push_ids() {
    let mut db = db();
    let (status, first) = call(&mut db, "POST", "/list.json?ns=t1", r#""v""#);
    assert_eq!(status, 200);
    let (_, second) = call(&mut db, "POST", "/list.json?ns=t1", r#""w""#);
    let id = |body: &str| body.trim_start_matches(r#"{"name":""#).trim_end_matches(r#""}"#).to_owned();
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
    for body in [r#"{"q":1,"q/r":2}"#, "[1,2]", "5", r#"{"a.b":1}"#, r#"{"a":{"b.c":1}}"#, r#"{"/":1}"#] {
        assert_eq!(call(&mut db, "PATCH", "/x.json?ns=v1", body), (400, message.clone()), "{body}");
    }
    assert_eq!(call(&mut db, "PATCH", "/x.json?ns=v1", "{}"), (200, "{}".to_owned()));
    assert_eq!(call(&mut db, "PATCH", "/x.json?ns=v1", r#"{"a//b":1}"#), (200, r#"{"a":{"b":1}}"#.to_owned()));
    assert_eq!(call(&mut db, "PATCH", "/x.json?ns=v1", r#"{"a":null,"b":2}"#), (200, r#"{"a":null,"b":2}"#.to_owned()));
    assert_eq!(call(&mut db, "GET", "/x.json?ns=v1", ""), (200, r#"{"b":2}"#.to_owned()));
}

#[test]
fn etags_and_conditional_writes() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1,"y":{"z":"s"}}"#);
    let response = send(&mut db, "GET", "/a.json?ns=t1", &[("X-Firebase-ETag", "true")], "");
    assert_eq!(header(&response, "ETag"), Some("6CNhL/bRBr4qg3PQLZRyxlcsmkg="));
    assert_eq!(header(&response, "Access-Control-Expose-Headers"), Some("ETag"));
    let response = send(&mut db, "GET", "/missing.json?ns=t1", &[("X-Firebase-ETag", "true")], "");
    assert_eq!(header(&response, "ETag"), Some("null_etag"));

    let refused = send(&mut db, "PUT", "/a/x.json?ns=t1", &[("if-match", "wrong")], "2");
    assert_eq!(refused.status, 412);
    assert_eq!(refused.body, b"1");
    assert_eq!(header(&refused, "ETag"), Some("YPVfR2bXt/lcDjiQZ8pOkAd3qkQ="));

    let accepted = send(&mut db, "PUT", "/a/x.json?ns=t1", &[("if-match", "YPVfR2bXt/lcDjiQZ8pOkAd3qkQ=")], "2");
    assert_eq!((accepted.status, accepted.body.as_slice()), (200, &b"2"[..]));
    assert_eq!(send(&mut db, "PUT", "/new.json?ns=t1", &[("if-match", "null_etag")], "5").status, 200);

    let deleted = send(&mut db, "DELETE", "/zz.json?ns=q1", &[("if-match", "wrong")], "");
    assert_eq!((deleted.status, header(&deleted, "ETag")), (412, Some("null_etag")));

    let unsupported = error("The 'if-match' header is not supported with GET, PATCH or POST requests");
    for method in ["GET", "PATCH", "POST"] {
        let response = send(&mut db, method, "/zz.json?ns=q1", &[("if-match", "null_etag")], r#"{"a":1}"#);
        assert_eq!(response.status, 400, "{method}");
        assert_eq!(String::from_utf8(response.body).unwrap(), unsupported);
    }

    let written = send(&mut db, "PUT", "/d/a/h.json?ns=q1", &[("X-Firebase-ETag", "true")], "7");
    assert_eq!(header(&written, "ETag"), Some("7wQgMram7RVqVIg/xRZWPfygGx0="));
    let silent = send(&mut db, "PUT", "/x.json?ns=v1&print=silent", &[("X-Firebase-ETag", "true")], "1");
    assert_eq!((silent.status, header(&silent, "ETag")), (204, Some("YPVfR2bXt/lcDjiQZ8pOkAd3qkQ=")));
}

#[test]
fn print_shallow_export_callback_and_download() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=t1", r#"{"w":3,"x":1,"y":{"z":"t"}}"#);
    assert_eq!(
        call(&mut db, "GET", "/a.json?ns=t1&print=pretty", ""),
        (200, "{\n  \"w\" : 3,\n  \"x\" : 1,\n  \"y\" : {\n    \"z\" : \"t\"\n  }\n}".to_owned())
    );
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1&print=bogus", "").1, r#"{"w":3,"x":1,"y":{"z":"t"}}"#);
    for method in ["GET", "PUT", "POST", "PATCH", "DELETE"] {
        let body = if method == "PATCH" { r#"{"q":1}"# } else { "1" };
        let response = send(&mut db, method, "/s.json?ns=t1&print=silent", &[], body);
        assert_eq!((response.status, response.body.len()), (204, 0), "{method}");
    }
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1&shallow=true", ""), (200, r#"{"w":true,"x":true,"y":true}"#.to_owned()));
    assert_eq!(call(&mut db, "GET", "/a/x.json?ns=t1&shallow=true", ""), (200, "1".to_owned()));
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1&shallow=yes", "").1, r#"{"w":3,"x":1,"y":{"z":"t"}}"#);
    call(&mut db, "PUT", "/e.json?ns=t1", r#"{"k":{".value":"v",".priority":"p"},".priority":1}"#);
    assert_eq!(call(&mut db, "GET", "/e.json?ns=t1&format=export", "").1, r#"{".priority":1,"k":{".value":"v",".priority":"p"}}"#);
    assert_eq!(call(&mut db, "GET", "/e.json?ns=t1&shallow=true&format=export", "").1, r#"{".priority":true,"k":true}"#);
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1&format=bogus", ""), (400, error("Export format must be export if present")));

    let jsonp = send(&mut db, "GET", "/a/x.json?ns=t1&callback=cb", &[], "");
    assert_eq!(header(&jsonp, "Content-Type"), Some("application/javascript; charset=utf-8"));
    assert_eq!(jsonp.body, b"/**/ cb(1);");
    let download = send(&mut db, "GET", "/a/x.json?ns=t1&download=f.json", &[], "");
    assert_eq!(header(&download, "Content-Disposition"), Some("attachment; filename=\"f.json\""));
    assert_eq!(header(&download, "Content-Type"), Some("application/octet-stream; charset=utf-8"));
    assert_eq!(download.body, b"1");
}

#[test]
fn method_override_options_and_unsupported_methods() {
    let mut db = db();
    call(&mut db, "PUT", "/a.json?ns=t1", r#"{"x":1}"#);
    let deleted = send(&mut db, "POST", "/a/x.json?ns=t1", &[("X-HTTP-Method-Override", "DELETE")], "");
    assert_eq!((deleted.status, deleted.body.as_slice()), (200, &b"null"[..]));
    let options = send(&mut db, "OPTIONS", "/a.json?ns=t1", &[], "");
    assert_eq!(options.status, 200);
    assert_eq!(header(&options, "Allow"), Some("OPTIONS,GET,POST,PUT,DELETE,PATCH"));
    assert_eq!(header(&options, "Access-Control-Allow-Methods"), Some("OPTIONS,GET,POST,PUT,DELETE,PATCH"));
    assert_eq!(call(&mut db, "HEAD", "/a.json?ns=t1", ""), (405, error("Unsupported request type")));
}

#[test]
fn write_size_limit_values_are_checked() {
    let mut db = db();
    for limit in ["tiny", "small", "medium", "large", "unlimited"] {
        assert_eq!(call(&mut db, "PUT", &format!("/a.json?ns=q1&writeSizeLimit={limit}"), "1").0, 200);
    }
    assert_eq!(
        call(&mut db, "PUT", "/a.json?ns=q1&writeSizeLimit=bogus", "1"),
        (400, error("writeSizeLimit should be one of {medium, tiny, large, unlimited, small}"))
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
        ("orderBy=\"h\"&endAt=5&endBefore=1", "Only one of endBefore and endAt may be specified"),
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
        assert_eq!(call(&mut db, "GET", &format!("/d.json?ns=q1&{query}"), ""), (400, error(message)), "{query}");
    }
    assert_eq!(
        call(&mut db, "PUT", "/d.json?ns=q1&orderBy=\"$key\"", "1"),
        (400, error("Querying related parameters not supported on this request type"))
    );
}

#[test]
fn child_and_value_orders_need_a_declared_index() {
    let mut db = query_db();
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"h\"", ""),
        (400, error("Index not defined, add \".indexOn\": \"h\", for path \"/d\", to the rules"))
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"$value\"&limitToFirst=2", ""),
        (400, error("Index not defined, add \".indexOn\": \".value\", for path \"/d\", to the rules"))
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"n/q\"", ""),
        (400, error("Index not defined, add \".indexOn\": \"n/q\", for path \"/d\", to the rules"))
    );
    // Not observed on the official emulator (it has no rules here): a declared index serves
    // the query.
    db.declare_index("q1", &Path::from_keys(["d"]), "h");
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"h\"&startAt=2&limitToFirst=2", ""),
        (200, r#"{"a":{"h":3},"c":{"h":2}}"#.replace(r#"{"h":3}"#, r#"{"h":3,"n":"x"}"#))
    );
}

#[test]
fn key_and_priority_queries() {
    let mut db = query_db();
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"$key\"&startAt=\"b\"", ""),
        (200, r#"{"b":{"h":1},"c":{"h":2},"d":{"n":"y"}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"$key\"&limitToFirst=2", ""),
        (200, r#"{"2":{"h":5},"10":{"h":5}}"#.to_owned())
    );
    assert_eq!(
        call(&mut db, "GET", "/d.json?ns=q1&orderBy=\"$priority\"&limitToFirst=2", ""),
        (200, r#"{"2":{"h":5},"10":{"h":5}}"#.to_owned())
    );
    call(&mut db, "PUT", "/k.json?ns=s1", r#"{"z":1,"-1":2,"01":3,"1":4,"a":5,".priority":"p"}"#);
    assert_eq!(
        call(&mut db, "GET", "/k.json?ns=s1&orderBy=\"$key\"&startAt=\"1\"&endAt=\"a\"", "").1,
        r#"{"1":4,"01":3,"a":5}"#
    );
    assert_eq!(call(&mut db, "GET", "/k.json?ns=s1&orderBy=\"$priority\"&startAt=1,\"a\"", "").1, "{}");
    assert_eq!(call(&mut db, "GET", "/k.json?ns=s1&orderBy=\"$key\"&equalTo=\"z\"&limitToLast=1", "").1, r#"{"z":1}"#);
    assert_eq!(call(&mut db, "GET", "/k.json?ns=s1&orderBy=\"$priority\"&startAt=true", "").1, "{}");
    assert_eq!(
        call(&mut db, "GET", "/k.json?ns=s1&orderBy=\"$priority\"&startAt={}", "").1,
        r#"{"-1":2,"1":4,"01":3,"a":5,"z":1}"#
    );
    assert_eq!(call(&mut db, "GET", "/k.json?ns=s1&orderBy=\"$key\"&startAt=\"b\"&print=pretty", "").1, "{\n  \"z\" : 1\n}");
    assert_eq!(call(&mut db, "GET", "/k/a.json?ns=s1&orderBy=\"$key\"", ""), (200, "5".to_owned()));
    assert_eq!(call(&mut db, "GET", "/nothing.json?ns=s1&orderBy=\"$key\"", ""), (200, "null".to_owned()));
}

#[test]
fn auth_parameters_are_accepted_while_rules_allow_everything() {
    let mut db = query_db();
    for target in ["/d/b.json?ns=q1&auth=abc", "/d/b.json?ns=q1&access_token=abc"] {
        assert_eq!(call(&mut db, "GET", target, ""), (200, r#"{"h":1}"#.to_owned()));
    }
    let bearer = send(&mut db, "GET", "/d/b.json?ns=q1", &[("Authorization", "Bearer abc")], "");
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
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1", ""), (401, error("Permission denied")));
    assert_eq!(call(&mut db, "PUT", "/a.json?ns=t1", "1"), (401, error("Permission denied")));
    let owner = send(&mut db, "PUT", "/a.json?ns=t1", &[("Authorization", "Bearer owner")], "1");
    assert_eq!(owner.status, 200);
    assert_eq!(call(&mut db, "GET", "/a.json?ns=t1&access_token=owner", ""), (200, "1".to_owned()));
}

#[test]
fn numbers_render_in_java_form() {
    let mut db = db();
    assert_eq!(
        call(&mut db, "PUT", "/big.json?ns=s1", r#"{"a":-0,"b":100000000000000000000,"c":1.0E-5,"d":0.001,"g":0.1}"#).1,
        r#"{"a":0,"b":1.0E20,"c":1.0E-5,"d":0.001,"g":0.1}"#
    );
}
