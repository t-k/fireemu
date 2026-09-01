//! Parser coverage for the native Rules subset (spec 13.3, 13.4).

use fireemu_core_rules::ast::{ExprKind, Item, Method, PathSegment};
use fireemu_core_rules::parse::parse_ruleset;

const SAMPLE: &str = r#"
rules_version = '2';
service cloud.firestore {
  // Helper functions
  function isSignedIn() {
    return request.auth != null;
  }
  function isOwner(uid) {
    let me = request.auth.uid;
    return isSignedIn() && me == uid;
  }
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if isOwner(userId);
      allow create, update: if isOwner(userId)
        && request.resource.data.keys().hasOnly(['name', 'age'])
        && request.resource.data.age is int
        && request.resource.data.age >= 0;
      allow delete: if false;
      match /posts/{postId} {
        allow read: if resource.data.visibility in ['public', 'unlisted'];
        allow write: if get(/databases/$(database)/documents/users/$(userId)).data.role == "admin";
      }
    }
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
"#;

#[test]
fn parses_a_realistic_ruleset() {
    let ruleset = parse_ruleset(SAMPLE).unwrap();
    assert_eq!(ruleset.version.as_deref(), Some("2"));
    assert_eq!(ruleset.services.len(), 1);
    let service = &ruleset.services[0];
    assert_eq!(service.name, "cloud.firestore");
    let functions: Vec<&str> = service
        .items
        .iter()
        .filter_map(|i| match i {
            Item::Function(f) => Some(f.name.as_str()),
            Item::Match(_) => None,
        })
        .collect();
    assert_eq!(functions, ["isSignedIn", "isOwner"]);
    let root = service
        .items
        .iter()
        .find_map(|i| match i {
            Item::Match(m) => Some(m),
            Item::Function(_) => None,
        })
        .unwrap();
    assert_eq!(root.path.len(), 3);
    assert!(matches!(&root.path[1], PathSegment::Capture { name, .. } if name == "database"));
    let users = match &root.items[0] {
        Item::Match(m) => m,
        Item::Function(_) => panic!(),
    };
    assert_eq!(users.allows.len(), 3);
    assert_eq!(
        users.allows[1].methods,
        vec![Method::Create, Method::Update]
    );
    let wildcard = match &root.items[1] {
        Item::Match(m) => m,
        Item::Function(_) => panic!(),
    };
    assert!(
        matches!(&wildcard.path[0], PathSegment::RecursiveWildcard { name, .. } if name == "document")
    );
}

#[test]
fn expression_precedence_and_forms() {
    let src = "rules_version = '2';\nservice cloud.firestore {\n  match /a/{b} {\n    allow read: if 1 + 2 * 3 == 7 && !(false || true) ? x.y[0](1) : -z;\n  }\n}";
    let ruleset = parse_ruleset(src).unwrap();
    let m = match &ruleset.services[0].items[0] {
        Item::Match(m) => m,
        Item::Function(_) => panic!(),
    };
    let cond = m.allows[0].condition.as_ref().unwrap();
    assert!(matches!(cond.kind(), ExprKind::Ternary { .. }));
    // Every node carries the extent a coverage report is keyed by.
    assert_eq!(cond.span.line, 4);
    assert!(cond.end > cond.span.offset);
}

#[test]
fn list_literals_accept_one_trailing_comma() {
    let src = r#"
service cloud.firestore {
  function allowedValues() {
    return [
      "one",
      "two",
    ];
  }
}
"#;
    let ruleset = parse_ruleset(src).unwrap();
    let function = match &ruleset.services[0].items[0] {
        Item::Function(function) => function,
        Item::Match(_) => panic!(),
    };
    let ExprKind::List(items) = function.body.kind() else {
        panic!("expected list return, got {:?}", function.body.kind());
    };
    assert_eq!(items.len(), 2);
}

#[test]
fn list_literals_reject_missing_expressions() {
    for literal in ["[, 1]", "[1, , 2]", "[1, ,]"] {
        let src =
            format!("service cloud.firestore {{ function invalid() {{ return {literal}; }} }}");
        assert!(parse_ruleset(&src).is_err(), "accepted {literal}");
    }
}

#[test]
fn final_return_statement_accepts_optional_semicolon() {
    for expression in [
        "true",
        "request.auth != null\n      && request.auth.uid == 'owner'",
        "[\n      'one',\n      'two',\n    ]",
    ] {
        for terminator in ["", ";"] {
            let src = format!(
                "service cloud.firestore {{\n  function allowed() {{\n    return {expression}{terminator}\n  }}\n}}"
            );
            parse_ruleset(&src)
                .unwrap_or_else(|error| panic!("rejected {expression:?}{terminator}: {error}"));
        }
    }
}

#[test]
fn final_return_statement_does_not_weaken_other_separators() {
    for body in [
        "let value = true\n    return value;",
        "return true\n    let value = false;",
        "return true\n    return false;",
    ] {
        let src =
            format!("service cloud.firestore {{\n  function invalid() {{\n    {body}\n  }}\n}}");
        assert!(parse_ruleset(&src).is_err(), "accepted {body:?}");
    }
}

#[test]
fn path_literals_with_bindings_parse_in_expressions() {
    let src = "service cloud.firestore {\n  match /a/{b} {\n    allow read: if exists(/databases/$(database)/documents/x/$(b + 'y'));\n  }\n}";
    let ruleset = parse_ruleset(src).unwrap();
    let m = match &ruleset.services[0].items[0] {
        Item::Match(m) => m,
        Item::Function(_) => panic!(),
    };
    match m.allows[0].condition.as_ref().unwrap().kind() {
        ExprKind::Call { args, .. } => match args[0].kind() {
            ExprKind::Path(segments) => {
                assert_eq!(segments.len(), 5);
                assert!(matches!(&segments[1], PathSegment::Binding(_)));
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

#[test]
fn syntax_errors_carry_positions() {
    let err =
        parse_ruleset("service cloud.firestore {\n  match /a {\n    allow read: if ;\n  }\n}")
            .unwrap_err();
    assert_eq!(err.line, 3);
    assert!(err.column > 0);
    let err = parse_ruleset("service cloud.firestore {").unwrap_err();
    assert!(err.message.contains("expected"));
    let err = parse_ruleset(
        "service cloud.firestore {\n match /a/{b} {\n allow frobnicate: if true;\n }\n}",
    )
    .unwrap_err();
    assert!(err.message.contains("frobnicate") || err.message.contains("method"));
}

#[test]
fn input_budget_rejects_oversized_or_control_character_sources() {
    let with_nul =
        "service cloud.firestore {\n match /a {\n allow read: if 'a\u{0}b' == 'x';\n }\n}";
    assert!(parse_ruleset(with_nul).is_err());
}

#[test]
fn parser_accepts_firebase_null_escape_pattern() {
    let source = r#"
rules_version = '2';
service cloud.firestore {
  function isValidString(data) {
    return data.matches(".*(\r|\n|\\0|\u0000|\x00)+.*") == false;
  }
}
"#;

    parse_ruleset(source).unwrap();
}

#[test]
fn invalid_regex_diagnostics_escape_control_characters() {
    let source = r#"
rules_version = '2';
service cloud.firestore {
  function invalid(data) {
    return data.matches("\u0000(?=x)");
  }
}
"#;

    let error = parse_ruleset(source).unwrap_err();
    assert!(
        error
            .message
            .chars()
            .all(|character| !character.is_control()),
        "{:?}",
        error.message
    );
    assert!(error.message.contains("\\0"), "{}", error.message);
}

#[test]
fn invalid_regex_diagnostics_escape_unicode_format_characters() {
    let source = r#"
rules_version = '2';
service cloud.firestore {
  function invalid(data) {
    return data.matches("\u202e(?=x)");
  }
}
"#;

    let error = parse_ruleset(source).unwrap_err();
    assert!(!error.message.contains('\u{202e}'), "{}", error.message);
    assert!(error.message.contains("\\u{202e}"), "{}", error.message);
}
