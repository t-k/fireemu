//! What import and export use: the namespaces the server knows (`/.inspect/databases.json`),
//! `disableTriggers`, the export text of a namespace and the import of one. Unless a test says
//! otherwise, every expected answer is what the official emulator (firebase-database-emulator
//! v4.11.2) answered for the same requests.

use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_792_464_733_000;
const OWNER: &[(&str, &str)] = &[("Authorization", "Bearer owner")];

fn call(
    db: &mut Database,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => {
            (response.status, String::from_utf8(response.body).unwrap())
        }
        Handled::Stream { .. } => panic!("stream"),
    }
}

fn error(message: &str) -> String {
    format!(
        "{{\n  \"error\" : \"{}\"\n}}\n",
        message.replace('"', "\\\"")
    )
}

#[test]
fn the_namespaces_the_server_knows_are_listed() {
    let mut db = Database::new(RestOptions::default(), 1);
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/.inspect/databases.json?ns=demo-p",
            OWNER,
            ""
        ),
        (200, r#"[{"name":"demo-p"}]"#.to_owned())
    );
    for (ns, body) in [
        ("demo-p-default-rtdb", r#"{"a":1}"#),
        ("other-default-rtdb", "1"),
        ("emptyns", "null"),
    ] {
        call(&mut db, "PUT", &format!("/.json?ns={ns}"), OWNER, body);
    }
    // Every namespace a request reached, by name; the official emulator lists them in an order
    // of its own (provisional: by name here). No credential is needed.
    let listed = r#"[{"name":"demo-p"},{"name":"demo-p-default-rtdb"},{"name":"emptyns"},{"name":"other-default-rtdb"}]"#;
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/.inspect/databases.json?ns=demo-p",
            &[],
            ""
        ),
        (200, listed.to_owned())
    );
    // Without ns, the default namespace is the one asked about.
    let (_, body) = call(&mut db, "GET", "/.inspect/databases.json", OWNER, "");
    assert!(body.contains(r#"{"name":"fake-server"}"#), "{body}");
    assert_eq!(
        call(&mut db, "POST", "/.inspect/databases.json?ns=p", OWNER, "1"),
        (405, error("Unsupported request type"))
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/.inspect/databases.json?ns=bad.ns",
            OWNER,
            ""
        ),
        (403, error("Invalid Firebase database name"))
    );
    for other in ["/.inspect/foo.json?ns=p", "/.inspect/databases?ns=p"] {
        assert_eq!(
            call(&mut db, "GET", other, OWNER, ""),
            (404, error("404 Not Found")),
            "{other}"
        );
    }
}

#[test]
fn disable_triggers_is_checked_on_writes_and_needs_an_administrator() {
    let mut db = Database::new(RestOptions::default(), 1);
    assert_eq!(
        call(&mut db, "GET", "/.json?ns=p2&disableTriggers=true", &[], "").0,
        200
    );
    let refused = error(
        "Only users with firebasedatabase.instances.update permissions are allowed to specify disableTriggers",
    );
    assert_eq!(
        call(
            &mut db,
            "PATCH",
            "/.json?ns=p2&disableTriggers=true",
            &[],
            r#"{"a":1}"#
        ),
        (400, refused.clone())
    );
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/.json?ns=p2&disableTriggers=true&auth=x",
            &[],
            "1"
        ),
        (400, refused)
    );
    assert_eq!(
        call(&mut db, "PUT", "/.json?ns=p2&disableTriggers=bad", &[], "1"),
        (400, error("disableTriggers should be one of {true, false}"))
    );
    assert_eq!(
        call(
            &mut db,
            "POST",
            "/.json?ns=p2&disableTriggers=false",
            OWNER,
            "1"
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/.json?ns=p2&disableTriggers=true",
            &[("Authorization", "Bearer x")],
            "1"
        ),
        (200, "1".to_owned())
    );
}

#[test]
fn a_namespace_is_exported_as_its_export_format_read_and_imported_back() {
    let mut db = Database::new(RestOptions::default(), 1);
    call(
        &mut db,
        "PUT",
        "/.json?ns=a-default-rtdb",
        OWNER,
        r#"{"a":{"b":1,".priority":3},"s":"x"}"#,
    );
    call(&mut db, "PUT", "/.json?ns=gone", OWNER, r#"{"x":1}"#);
    call(&mut db, "DELETE", "/.json?ns=gone", OWNER, "");
    call(&mut db, "GET", "/.json?ns=never", OWNER, "");
    // Only namespaces with data, with what `format=export` answers.
    assert_eq!(
        db.export_texts(),
        vec![(
            "a-default-rtdb".to_owned(),
            r#"{"a":{".priority":3.0,"b":1},"s":"x"}"#.to_owned()
        )]
    );
    let mut imported = Database::new(RestOptions::default(), 2);
    imported
        .import_text(
            "a-default-rtdb",
            r#"{"a":{".priority":3.0,"b":1},"s":"x"}"#,
            NOW,
        )
        .unwrap();
    imported
        .import_text("leaf", r#"{".value":5,".priority":1}"#, NOW)
        .unwrap();
    // An imported namespace is exported even when it holds nothing, as firebase-tools does.
    imported.import_text("empty", "null", NOW).unwrap();
    assert_eq!(
        imported.export_texts(),
        vec![
            (
                "a-default-rtdb".to_owned(),
                r#"{"a":{".priority":3.0,"b":1},"s":"x"}"#.to_owned()
            ),
            ("empty".to_owned(), "null".to_owned()),
            (
                "leaf".to_owned(),
                r#"{".value":5,".priority":1.0}"#.to_owned()
            ),
        ]
    );
    // Refusals are the official emulator's answers to the import request.
    assert_eq!(
        imported.import_text("p3", "{bad", NOW),
        Err("Invalid data; couldn't parse JSON object, array, or value.".to_owned())
    );
    assert_eq!(
        imported.import_text("bad.ns", "1", NOW),
        Err("Invalid Firebase database name".to_owned())
    );
}

#[test]
fn the_inspect_route_can_require_the_owner() {
    // Under strict and a locked database (review RTDB-04 S1) only the owner lists namespaces,
    // and a refused request creates none; firebase-tools sends the owner credential.
    let options = RestOptions {
        inspect_needs_owner: true,
        ..RestOptions::default()
    };
    let mut db = Database::new(options, 1);
    call(&mut db, "PUT", "/.json?ns=kept", OWNER, "1");
    for headers in [&[][..], &[("Authorization", "Bearer someone")][..]] {
        assert_eq!(
            call(
                &mut db,
                "GET",
                "/.inspect/databases.json?ns=probe",
                headers,
                ""
            ),
            (401, error("Permission denied"))
        );
    }
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/.inspect/databases.json?ns=kept",
            OWNER,
            ""
        ),
        (200, r#"[{"name":"kept"}]"#.to_owned())
    );
    assert_eq!(
        call(
            &mut db,
            "GET",
            "/.inspect/databases.json?ns=kept&access_token=owner",
            &[],
            ""
        )
        .0,
        200
    );
}
