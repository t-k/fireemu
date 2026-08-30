//! Parser coverage for the native Rules subset (spec 13.3, 13.4).

use fireemu_core_rules::ast::{Expr, Item, Method, PathSegment};
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
    assert!(matches!(cond, Expr::Ternary { .. }));
}

#[test]
fn path_literals_with_bindings_parse_in_expressions() {
    let src = "service cloud.firestore {\n  match /a/{b} {\n    allow read: if exists(/databases/$(database)/documents/x/$(b + 'y'));\n  }\n}";
    let ruleset = parse_ruleset(src).unwrap();
    let m = match &ruleset.services[0].items[0] {
        Item::Match(m) => m,
        Item::Function(_) => panic!(),
    };
    match m.allows[0].condition.as_ref().unwrap() {
        Expr::Call { args, .. } => match &args[0] {
            Expr::Path(segments) => {
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
