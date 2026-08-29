//! Native Rules evaluation subset (Milestone H core): request.auth from Auth claims,
//! deny-by-default, budgets from the catalog, unsupported built-ins fail closed.

use std::collections::BTreeMap;

use ftd_core_rules::eval::{evaluate_request, Decision, DenyReason, Method, RequestContext};
use ftd_core_rules::parse::parse_ruleset;
use ftd_core_rules::value::{AuthContext, RulesValue};

const RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function isSignedIn() { return request.auth != null; }
    function isOwner(uid) { return isSignedIn() && request.auth.uid == uid; }
    function hasTotp() {
      return request.auth.token.firebase.sign_in_second_factor == 'totp';
    }
    match /users/{userId} {
      allow read: if isOwner(userId);
      allow write: if isOwner(userId) && hasTotp();
      match /notes/{noteId} {
        allow read: if isOwner(userId) || resource.data.visibility == 'public';
        allow create: if isOwner(userId) && request.resource.data.title is string
          && request.resource.data.title.size() <= 100
          && request.resource.data.keys().hasOnly(['title', 'visibility']);
      }
    }
    match /admin/{document=**} {
      allow read, write: if request.auth.token.role == 'admin';
    }
    match /public/{doc} {
      allow read;
    }
  }
}
";

fn auth(uid: &str, totp: bool, role: Option<&str>) -> AuthContext {
    let mut token = BTreeMap::new();
    token.insert("sub".to_owned(), RulesValue::String(uid.to_owned()));
    token.insert(
        "email".to_owned(),
        RulesValue::String(format!("{uid}@example.com")),
    );
    let mut firebase = BTreeMap::new();
    firebase.insert(
        "sign_in_provider".to_owned(),
        RulesValue::String("password".to_owned()),
    );
    if totp {
        firebase.insert(
            "sign_in_second_factor".to_owned(),
            RulesValue::String("totp".to_owned()),
        );
    }
    token.insert("firebase".to_owned(), RulesValue::Map(firebase));
    if let Some(r) = role {
        token.insert("role".to_owned(), RulesValue::String(r.to_owned()));
    }
    AuthContext {
        uid: uid.to_owned(),
        token,
    }
}

fn ctx(method: Method, path: &str, auth: Option<AuthContext>) -> RequestContext {
    RequestContext {
        method,
        path: path.to_owned(),
        auth,
        resource: None,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
    }
}

fn doc(entries: &[(&str, RulesValue)]) -> RulesValue {
    let mut m = BTreeMap::new();
    m.insert(
        "data".to_owned(),
        RulesValue::Map(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ),
    );
    RulesValue::Map(m)
}

#[test]
fn owner_can_read_but_write_requires_totp() {
    let ruleset = parse_ruleset(RULES).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Get,
            "/databases/(default)/documents/users/alice",
            Some(auth("alice", false, None)),
        ),
    );
    assert!(matches!(r.decision, Decision::Allow), "{r:?}");
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Update,
            "/databases/(default)/documents/users/alice",
            Some(auth("alice", false, None)),
        ),
    );
    assert!(matches!(r.decision, Decision::Deny(_)));
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Update,
            "/databases/(default)/documents/users/alice",
            Some(auth("alice", true, None)),
        ),
    );
    assert!(matches!(r.decision, Decision::Allow), "{r:?}");
    // Someone else, even with TOTP, is denied.
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Update,
            "/databases/(default)/documents/users/alice",
            Some(auth("bob", true, None)),
        ),
    );
    assert!(matches!(r.decision, Decision::Deny(_)));
}

#[test]
fn unauthenticated_requests_are_denied_by_default_and_public_reads_allowed() {
    let ruleset = parse_ruleset(RULES).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Get,
            "/databases/(default)/documents/users/alice",
            None,
        ),
    );
    assert!(
        matches!(r.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{r:?}"
    );
    let r = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/public/x", None),
    );
    assert!(matches!(r.decision, Decision::Allow));
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Get,
            "/databases/(default)/documents/nowhere/x",
            None,
        ),
    );
    assert!(matches!(
        r.decision,
        Decision::Deny(DenyReason::NoMatchingRule)
    ));
}

#[test]
fn nested_matches_resource_data_and_request_resource_validation() {
    let ruleset = parse_ruleset(RULES).unwrap();
    let path = "/databases/(default)/documents/users/alice/notes/n1";
    let mut public = ctx(Method::Get, path, None);
    public.resource = Some(doc(&[("visibility", RulesValue::String("public".into()))]));
    assert!(matches!(
        evaluate_request(&ruleset, &public).decision,
        Decision::Allow
    ));
    let mut private = ctx(Method::Get, path, None);
    private.resource = Some(doc(&[("visibility", RulesValue::String("private".into()))]));
    assert!(matches!(
        evaluate_request(&ruleset, &private).decision,
        Decision::Deny(_)
    ));

    let mut create = ctx(Method::Create, path, Some(auth("alice", false, None)));
    create.request_resource = Some(doc(&[
        ("title", RulesValue::String("hello".into())),
        ("visibility", RulesValue::String("public".into())),
    ]));
    assert!(
        matches!(
            evaluate_request(&ruleset, &create).decision,
            Decision::Allow
        ),
        "{:?}",
        evaluate_request(&ruleset, &create)
    );
    let mut bad = ctx(Method::Create, path, Some(auth("alice", false, None)));
    bad.request_resource = Some(doc(&[("title", RulesValue::Int(5))]));
    assert!(matches!(
        evaluate_request(&ruleset, &bad).decision,
        Decision::Deny(_)
    ));
    let mut extra = ctx(Method::Create, path, Some(auth("alice", false, None)));
    extra.request_resource = Some(doc(&[
        ("title", RulesValue::String("x".into())),
        ("secret", RulesValue::Bool(true)),
    ]));
    assert!(matches!(
        evaluate_request(&ruleset, &extra).decision,
        Decision::Deny(_)
    ));
}

#[test]
fn recursive_wildcard_and_custom_claims() {
    let ruleset = parse_ruleset(RULES).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Delete,
            "/databases/(default)/documents/admin/a/b/c",
            Some(auth("root", false, Some("admin"))),
        ),
    );
    assert!(matches!(r.decision, Decision::Allow), "{r:?}");
    let r = evaluate_request(
        &ruleset,
        &ctx(
            Method::Delete,
            "/databases/(default)/documents/admin/a/b/c",
            Some(auth("root", false, Some("user"))),
        ),
    );
    assert!(matches!(r.decision, Decision::Deny(_)));
}

#[test]
fn unsupported_builtins_deny_instead_of_allowing() {
    let src = "service cloud.firestore {\n  match /databases/{db}/documents {\n    match /a/{x} {\n      allow read: if get(/databases/$(db)/documents/b/$(x)).data.ok == true || true;\n    }\n  }\n}";
    let ruleset = parse_ruleset(src).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
    );
    assert!(
        matches!(r.decision, Decision::Deny(DenyReason::Unsupported(_))),
        "{r:?}"
    );
}

#[test]
fn expression_budget_and_call_depth_are_enforced_from_the_catalog() {
    // A chain of 25 function frames exceeds RULES-FUNCTION-CALL-DEPTH (20) at runtime.
    use std::fmt::Write as _;
    let mut fns = String::new();
    for i in 0..25 {
        let body = if i + 1 < 25 {
            format!("f{}()", i + 1)
        } else {
            "true".to_owned()
        };
        writeln!(fns, "    function f{i}() {{ return {body}; }}").unwrap();
    }
    let src = format!("service cloud.firestore {{\n  match /databases/{{db}}/documents {{\n{fns}    match /a/{{x}} {{ allow read: if f0(); }}\n  }}\n}}");
    let ruleset = parse_ruleset(&src).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
    );
    assert!(
        matches!(
            r.decision,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "RULES-FUNCTION-CALL-DEPTH",
                ..
            })
        ),
        "{r:?}"
    );

    // 1,001 evaluated expressions: `true && true && ...` chained beyond the budget.
    let expr = std::iter::repeat_n("true", 1_100)
        .collect::<Vec<_>>()
        .join(" && ");
    let src = format!("service cloud.firestore {{\n  match /databases/{{db}}/documents {{\n    match /a/{{x}} {{ allow read: if {expr}; }}\n  }}\n}}");
    let ruleset = parse_ruleset(&src).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
    );
    assert!(
        matches!(
            r.decision,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "RULES-EXPRESSIONS-PER-REQUEST",
                ..
            })
        ),
        "{r:?}"
    );
    assert!(r.expressions_evaluated > 1_000);
    // Short-circuit: `false && <1,100 terms>` costs only a few expressions.
    let src = format!("service cloud.firestore {{\n  match /databases/{{db}}/documents {{\n    match /a/{{x}} {{ allow read: if false && ({expr}); }}\n  }}\n}}");
    let ruleset = parse_ruleset(&src).unwrap();
    let r = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
    );
    assert!(r.expressions_evaluated < 10, "{}", r.expressions_evaluated);
}

#[test]
fn auth_context_is_built_from_id_token_claims() {
    use ftd_core_auth::claims::{ClaimValue, CustomClaims, FirebaseClaims, IdTokenClaims};
    let mut custom = CustomClaims::default();
    custom
        .insert("role", ClaimValue::String("admin".into()))
        .unwrap();
    let claims = IdTokenClaims {
        iss: "https://securetoken.google.com/demo-app".into(),
        aud: "demo-app".into(),
        auth_time: 1,
        user_id: "u1".into(),
        sub: "u1".into(),
        iat: 1,
        exp: 3_601,
        email: Some("u1@example.com".into()),
        email_verified: true,
        firebase: FirebaseClaims {
            identities: BTreeMap::from([("email".to_owned(), vec!["u1@example.com".to_owned()])]),
            sign_in_provider: "password".into(),
            sign_in_second_factor: Some("totp".into()),
            second_factor_identifier: Some("mfa-1".into()),
        },
        custom,
    };
    let ctx = AuthContext::from_id_token_json(&claims.canonical_json()).unwrap();
    assert_eq!(ctx.uid, "u1");
    assert_eq!(
        ctx.token.get("role"),
        Some(&RulesValue::String("admin".into()))
    );
    match ctx.token.get("firebase") {
        Some(RulesValue::Map(m)) => assert_eq!(
            m.get("sign_in_second_factor"),
            Some(&RulesValue::String("totp".into()))
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ctx.token.get("email_verified"),
        Some(&RulesValue::Bool(true))
    );
}
