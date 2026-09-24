//! Native Rules evaluation subset (Milestone H core): request.auth from Auth claims,
//! deny-by-default, budgets from the catalog, unsupported built-ins fail closed.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fireemu_core_rules::eval::{
    evaluate_request, evaluate_request_traced_owned, Decision, DenyReason, Method, RequestContext,
    RulesService,
};
use fireemu_core_rules::parse::parse_ruleset;
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::{AuthContext, RulesValue};

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
        service: RulesService::Firestore,
        method,
        path: path.to_owned(),
        auth,
        resource: None,
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    }
}

fn balanced_and(leaves: usize) -> String {
    if leaves == 1 {
        return "true".to_owned();
    }
    let left = leaves / 2;
    format!(
        "({} && {})",
        balanced_and(left),
        balanced_and(leaves - left)
    )
}

fn rules_with_expensive_nonmatches(service: &str, allow: Option<&str>, allow_last: bool) -> String {
    let mut source = format!("rules_version = '2'; service {service} {{\n");
    if service == "cloud.firestore" {
        source.push_str("  match /databases/{database}/documents {\n");
    } else {
        source.push_str("  match /b/{bucket}/o {\n");
    }
    let exact_path = (0..90)
        .map(|segment| format!("segment{segment}"))
        .collect::<Vec<_>>()
        .join("/");
    let exact = |source: &mut String| {
        writeln!(source, "    match /{exact_path} {{").unwrap();
        if let Some(condition) = allow {
            writeln!(source, "      allow read{condition};").unwrap();
        }
        source.push_str("    }\n");
    };
    if !allow_last {
        exact(&mut source);
    }
    for index in 0..750 {
        writeln!(
            source,
            "    match /{{rest{index}=**}}/never{index} {{ allow read; }}"
        )
        .unwrap();
    }
    if allow_last {
        exact(&mut source);
    }
    source.push_str("  }\n}\n");
    source
}

fn long_request_path(service: RulesService) -> String {
    let prefix = match service {
        RulesService::Firestore => "/databases/(default)/documents",
        RulesService::Storage => "/b/demo/o",
    };
    format!(
        "{prefix}/{}",
        (0..90)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/")
    )
}

fn rules_with_over_budget_no_allow(service: &str) -> String {
    let mut source = format!("rules_version = '2'; service {service} {{\n");
    if service == "cloud.firestore" {
        source.push_str("  match /databases/{database}/documents {\n");
    } else {
        source.push_str("  match /b/{bucket}/o {\n");
    }
    for index in 0..750 {
        writeln!(
            source,
            "    match /{{rest{index}=**}} {{ allow read: if false; }}"
        )
        .unwrap();
    }
    source.push_str("  }\n}\n");
    source
}

#[test]
fn loaded_rules_allow_survives_later_match_path_work_budget() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let source = rules_with_expensive_nonmatches(service_name, Some(""), false);
        let loaded = LoadedRules::from_source(&source).unwrap();
        let ruleset = loaded.ruleset.as_ref().unwrap();
        let report = evaluate_request(
            ruleset,
            &RequestContext {
                service,
                method: Method::Get,
                path: long_request_path(service),
                auth: None,
                resource: None,
                request_resource: None,
                time_unix_nanos: 0,
                abstract_path: false,
                request_query: None,
            },
        );
        assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    }
}

#[test]
fn loaded_rules_allow_after_expensive_siblings_is_still_reachable() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let source = rules_with_expensive_nonmatches(service_name, Some(""), true);
        let loaded = LoadedRules::from_source(&source).unwrap();
        let ruleset = loaded.ruleset.as_ref().unwrap();
        let report = evaluate_request(
            ruleset,
            &RequestContext {
                service,
                method: Method::Get,
                path: long_request_path(service),
                auth: None,
                resource: None,
                request_resource: None,
                time_unix_nanos: 0,
                abstract_path: false,
                request_query: None,
            },
        );
        assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    }
}

#[test]
fn loaded_rules_allow_after_structurally_impossible_siblings_is_reachable() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        let mut source = format!("rules_version = '2'; service {service_name} {{\n  {root}\n");
        for index in 0..750 {
            writeln!(
                source,
                "    match /{{rest{index}=**}}/segment89/{{tail{index}}} {{ allow read: if false; }}"
            )
            .unwrap();
        }
        let allow_path = (0..90)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/");
        writeln!(
            source,
            "    match /{allow_path} {{ allow read; }}\n  }}\n}}\n"
        )
        .unwrap();

        let loaded = LoadedRules::from_source(&source).unwrap();
        let report = evaluate_request(
            loaded.ruleset.as_ref().unwrap(),
            &RequestContext {
                service,
                method: Method::Get,
                path: long_request_path(service),
                auth: None,
                resource: None,
                request_resource: None,
                time_unix_nanos: 0,
                abstract_path: false,
                request_query: None,
            },
        );
        assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    }
}

#[test]
fn loaded_rules_allow_after_equivalent_parent_children_is_reachable() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        for version in ["1", "2"] {
            let mut source =
                format!("rules_version = '{version}'; service {service_name} {{\n  {root}\n");
            if version == "2" {
                for index in 0..750 {
                    writeln!(
                        source,
                        "    match /{{prefix{index}=**}} {{ match /{{suffix{index}=**}}/segment40 {{ allow read; }} }}"
                    )
                    .unwrap();
                }
            } else {
                // Version 1 requires recursive wildcards to be the final path segment, so use
                // valid bounded parent/child patterns that cannot consume the full request.
                let parent_path = (0..8)
                    .map(|index| format!("segment{index}"))
                    .collect::<Vec<_>>()
                    .join("/");
                for index in 0..128 {
                    writeln!(
                        source,
                        "    match /{parent_path} {{ match /{{tail{index}}} {{ allow read; }} }}"
                    )
                    .unwrap();
                }
            }
            let allow_path = (0..90)
                .map(|index| format!("segment{index}"))
                .collect::<Vec<_>>()
                .join("/");
            writeln!(
                source,
                "    match /{allow_path} {{ allow read; }}\n  }}\n}}\n"
            )
            .unwrap();

            let loaded = LoadedRules::from_source(&source).unwrap();
            let report = evaluate_request(
                loaded.ruleset.as_ref().unwrap(),
                &RequestContext {
                    service,
                    method: Method::Get,
                    path: long_request_path(service),
                    auth: None,
                    resource: None,
                    request_resource: None,
                    time_unix_nanos: 0,
                    abstract_path: false,
                    request_query: None,
                },
            );
            assert!(matches!(report.decision, Decision::Allow), "{report:?}");
        }
    }
}

#[test]
fn loaded_rules_skip_partial_leaf_siblings_before_a_reachable_allow() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        let mut source = format!("rules_version = '2'; service {service_name} {{\n  {root}\n");
        for index in 0..750 {
            writeln!(
                source,
                "    match /{{rest{index}=**}}/segment0 {{ allow read; }}"
            )
            .unwrap();
        }
        let allow_path = (0..90)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/");
        writeln!(
            source,
            "    match /{allow_path} {{ allow read; }}\n  }}\n}}\n"
        )
        .unwrap();

        let loaded = LoadedRules::from_source(&source).unwrap();
        let report = evaluate_request(
            loaded.ruleset.as_ref().unwrap(),
            &RequestContext {
                service,
                method: Method::Get,
                path: long_request_path(service),
                auth: None,
                resource: None,
                request_resource: None,
                time_unix_nanos: 0,
                abstract_path: false,
                request_query: None,
            },
        );
        assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    }
}

#[test]
fn loaded_rules_skip_partial_leaf_siblings_that_match_an_early_prefix() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let allow_path = (0..90)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/");
        for allow_last in [false, true] {
            for allow in [false, true] {
                let root = if service == RulesService::Firestore {
                    "match /databases/{database}/documents {"
                } else {
                    "match /b/{bucket}/o {"
                };
                let allow_clause = if allow {
                    "allow read;"
                } else {
                    "allow read: if false;"
                };
                let mut source =
                    format!("rules_version = '2'; service {service_name} {{\n  {root}\n");
                if !allow_last {
                    writeln!(source, "    match /{allow_path} {{ {allow_clause} }}").unwrap();
                }
                for index in 0..750 {
                    writeln!(
                        source,
                        "    match /{{rest{index}=**}}/segment40/{{tail{index}}} {{ allow read; }}"
                    )
                    .unwrap();
                }
                if allow_last {
                    writeln!(source, "    match /{allow_path} {{ {allow_clause} }}").unwrap();
                }
                writeln!(source, "  }}\n}}\n").unwrap();

                let loaded = LoadedRules::from_source(&source).unwrap();
                let report = evaluate_request(
                    loaded.ruleset.as_ref().unwrap(),
                    &RequestContext {
                        service,
                        method: Method::Get,
                        path: long_request_path(service),
                        auth: None,
                        resource: None,
                        request_resource: None,
                        time_unix_nanos: 0,
                        abstract_path: false,
                        request_query: None,
                    },
                );
                if allow {
                    assert!(matches!(report.decision, Decision::Allow), "{report:?}");
                } else {
                    assert!(
                        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
                        "{report:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn loaded_rules_skip_partial_parent_siblings_before_a_reachable_allow() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        let allow_path = (0..90)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/");
        for allow_last in [false, true] {
            for allow in [false, true] {
                let allow_clause = if allow {
                    "allow read;"
                } else {
                    "allow read: if false;"
                };
                let mut source =
                    format!("rules_version = '2'; service {service_name} {{\n  {root}\n");
                if !allow_last {
                    writeln!(source, "    match /{allow_path} {{ {allow_clause} }}").unwrap();
                }
                for index in 0..750 {
                    writeln!(
                        source,
                        "    match /{{rest{index}=**}}/segment40 {{ match /{{tail{index}}} {{ allow read: if false; }} }}"
                    )
                    .unwrap();
                }
                if allow_last {
                    writeln!(source, "    match /{allow_path} {{ {allow_clause} }}").unwrap();
                }
                writeln!(source, "  }}\n}}\n").unwrap();

                let loaded = LoadedRules::from_source(&source).unwrap();
                let report = evaluate_request(
                    loaded.ruleset.as_ref().unwrap(),
                    &RequestContext {
                        service,
                        method: Method::Get,
                        path: long_request_path(service),
                        auth: None,
                        resource: None,
                        request_resource: None,
                        time_unix_nanos: 0,
                        abstract_path: false,
                        request_query: None,
                    },
                );
                if allow {
                    assert!(matches!(report.decision, Decision::Allow), "{report:?}");
                } else {
                    assert!(
                        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
                        "{report:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn loaded_rules_skip_parent_subtrees_with_only_partial_child_endpoints() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        let allow_path = (0..90)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/");
        for version in ["1", "2"] {
            for allow in [false, true] {
                let allow_clause = if allow {
                    "allow read;"
                } else {
                    "allow read: if false;"
                };
                let mut source =
                    format!("rules_version = '{version}'; service {service_name} {{\n  {root}\n");
                for index in 0..750 {
                    writeln!(
                        source,
                        "    match /{{prefix{index}=**}} {{ match /segment89 {{ allow read: if false; }} }}"
                    )
                    .unwrap();
                }
                writeln!(source, "    match /{allow_path} {{ {allow_clause} }}").unwrap();
                writeln!(source, "  }}\n}}\n").unwrap();

                let loaded = LoadedRules::from_source(&source).unwrap();
                let report = evaluate_request(
                    loaded.ruleset.as_ref().unwrap(),
                    &RequestContext {
                        service,
                        method: Method::Get,
                        path: long_request_path(service),
                        auth: None,
                        resource: None,
                        request_resource: None,
                        time_unix_nanos: 0,
                        abstract_path: false,
                        request_query: None,
                    },
                );
                if allow {
                    assert!(matches!(report.decision, Decision::Allow), "{report:?}");
                } else {
                    assert!(
                        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
                        "{report:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn loaded_rules_skip_partial_parent_children_before_a_valid_nested_allow() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        for version in ["1", "2"] {
            for allow_last in [false, true] {
                for allow in [false, true] {
                    let allow_clause = if allow {
                        "allow read;"
                    } else {
                        "allow read: if false;"
                    };
                    let valid_child =
                        format!("match /{{prefix=**}} {{ match /segment89 {{ {allow_clause} }} }}");
                    let mut source = format!(
                        "rules_version = '{version}'; service {service_name} {{\n  {root}\n"
                    );
                    if !allow_last {
                        writeln!(source, "    {valid_child}").unwrap();
                    }
                    for index in 0..750 {
                        writeln!(
                            source,
                            "    match /{{prefix{index}=**}} {{ match /wrong{index}/{{tail{index}}} {{ allow read; }} }}"
                        )
                        .unwrap();
                    }
                    if allow_last {
                        writeln!(source, "    {valid_child}").unwrap();
                    }
                    writeln!(source, "  }}\n}}\n").unwrap();

                    let loaded = LoadedRules::from_source(&source).unwrap();
                    let report = evaluate_request(
                        loaded.ruleset.as_ref().unwrap(),
                        &RequestContext {
                            service,
                            method: Method::Get,
                            path: long_request_path(service),
                            auth: None,
                            resource: None,
                            request_resource: None,
                            time_unix_nanos: 0,
                            abstract_path: false,
                            request_query: None,
                        },
                    );
                    if allow {
                        assert!(matches!(report.decision, Decision::Allow), "{report:?}");
                    } else {
                        assert!(
                            matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
                            "{report:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn partial_subtree_prefilter_preserves_covered_path_denial() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents/{document=**} {"
        } else {
            "match /b/{bucket}/o/{path=**} {"
        };
        for version in ["1", "2"] {
            let source = format!(
                "rules_version = '{version}'; service {service_name} {{\n  {root}\n    match /never {{ allow read; }}\n  }}\n}}\n"
            );
            let loaded = LoadedRules::from_source(&source).unwrap();
            let report = evaluate_request(
                loaded.ruleset.as_ref().unwrap(),
                &RequestContext {
                    service,
                    method: Method::Get,
                    path: long_request_path(service),
                    auth: None,
                    resource: None,
                    request_resource: None,
                    time_unix_nanos: 0,
                    abstract_path: false,
                    request_query: None,
                },
            );
            assert!(
                matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
                "{report:?}"
            );
        }
    }
}

#[test]
fn nested_parent_reachability_preserves_abstract_query_matches() {
    let rules = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents/{prefix=**} {\n    match /notes/{id} { allow list; }\n  }\n}";
    let path = "/databases/(default)/documents/fireemu-any-prefix/notes/fireemu-placeholder";
    assert!(allows(rules, &abstract_ctx(path, vec![])));
}

#[test]
fn loaded_rules_leaf_prefilter_preserves_v1_and_parent_children() {
    for service_name in ["cloud.firestore", "firebase.storage"] {
        let service = if service_name == "cloud.firestore" {
            RulesService::Firestore
        } else {
            RulesService::Storage
        };
        let root = if service == RulesService::Firestore {
            "match /databases/{database}/documents {"
        } else {
            "match /b/{bucket}/o {"
        };
        let mut source = format!("rules_version = '1'; service {service_name} {{\n  {root}\n");
        for index in 0..750 {
            writeln!(
                source,
                "    match /segment0/{{tail{index}}} {{ allow read; }}"
            )
            .unwrap();
        }
        writeln!(
            source,
            "    match /segment0 {{ match /segment1/{{rest=**}} {{ allow read; }} }}"
        )
        .unwrap();
        writeln!(source, "  }}\n}}\n").unwrap();

        let loaded = LoadedRules::from_source(&source).unwrap();
        let report = evaluate_request(
            loaded.ruleset.as_ref().unwrap(),
            &RequestContext {
                service,
                method: Method::Get,
                path: long_request_path(service),
                auth: None,
                resource: None,
                request_resource: None,
                time_unix_nanos: 0,
                abstract_path: false,
                request_query: None,
            },
        );
        assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    }
}

#[test]
fn loaded_rules_false_or_unresolved_expensive_matches_remain_denied() {
    let false_allow = rules_with_expensive_nonmatches("cloud.firestore", Some(": if false"), false);
    let loaded = LoadedRules::from_source(&false_allow).unwrap();
    let ruleset = loaded.ruleset.as_ref().unwrap();
    let report = evaluate_request(
        ruleset,
        &RequestContext {
            service: RulesService::Firestore,
            method: Method::Get,
            path: long_request_path(RulesService::Firestore),
            auth: None,
            resource: None,
            request_resource: None,
            time_unix_nanos: 0,
            abstract_path: false,
            request_query: None,
        },
    );
    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{report:?}"
    );

    for service in [RulesService::Firestore, RulesService::Storage] {
        let service_name = match service {
            RulesService::Firestore => "cloud.firestore",
            RulesService::Storage => "firebase.storage",
        };
        let source = rules_with_over_budget_no_allow(service_name);
        let loaded = LoadedRules::from_source(&source).unwrap();
        let ruleset = loaded.ruleset.as_ref().unwrap();
        let report = evaluate_request(
            ruleset,
            &RequestContext {
                service,
                method: Method::Get,
                path: long_request_path(service),
                auth: None,
                resource: None,
                request_resource: None,
                time_unix_nanos: 0,
                abstract_path: false,
                request_query: None,
            },
        );
        assert!(
            matches!(
                report.decision,
                Decision::Deny(DenyReason::BudgetExceeded {
                    limit_id: "FIREEMU-RULES-MATCH-WORK",
                    ..
                })
            ),
            "{report:?}"
        );
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
fn user_function_calls_resolve_in_the_definition_scope() {
    let ruleset = parse_ruleset(
        "rules_version = '2';\nservice cloud.firestore {\n  function decision() { return false; }\n  function gate() { return decision(); }\n  match /databases/{db}/documents {\n    function decision() { return true; }\n    match /notes/{id} { allow read: if gate(); }\n  }\n}",
    )
    .unwrap();
    let report = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/notes/n1", None),
    );

    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{report:?}"
    );
}

#[test]
fn user_function_does_not_capture_caller_match_bindings() {
    let ruleset = parse_ruleset(
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents/users/{uid} {\n    function owner() { return request.auth.uid == uid; }\n    function delegate(uid) { return owner(); }\n    allow read: if delegate(request.auth.uid);\n  }\n}",
    )
    .unwrap();
    let report = evaluate_request(
        &ruleset,
        &ctx(
            Method::Get,
            "/databases/(default)/documents/users/victim",
            Some(auth("attacker", false, None)),
        ),
    );

    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{report:?}"
    );

    let owner_report = evaluate_request(
        &ruleset,
        &ctx(
            Method::Get,
            "/databases/(default)/documents/users/victim",
            Some(auth("victim", false, None)),
        ),
    );
    assert!(
        matches!(owner_report.decision, Decision::Allow),
        "{owner_report:?}"
    );
}

#[test]
fn user_function_lexical_capture_survives_caller_parameter_and_let() {
    let ruleset = parse_ruleset(
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents/users/{owner} {\n    function isOwner() { return request.auth.uid == owner; }\n    function gate(owner) { let owner = request.auth.uid; return isOwner(); }\n    allow get: if gate(request.auth.uid);\n  }\n}",
    )
    .unwrap();
    let path = "/databases/(default)/documents/users/alice";
    let alice = evaluate_request(
        &ruleset,
        &ctx(Method::Get, path, Some(auth("alice", false, None))),
    );
    let bob = evaluate_request(
        &ruleset,
        &ctx(Method::Get, path, Some(auth("bob", false, None))),
    );

    assert!(matches!(alice.decision, Decision::Allow), "{alice:?}");
    assert!(
        matches!(bob.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{bob:?}"
    );
}

#[test]
fn nested_function_call_uses_each_declaration_scope_after_caller_shadowing() {
    let ruleset = parse_ruleset(
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents/users/{owner} {\n    function isOwner() { return request.auth.uid == owner; }\n    match /notes/{note} {\n      function gate(owner) { let owner = 'bob'; return isOwner(); }\n      allow get: if gate('bob');\n    }\n  }\n}",
    )
    .unwrap();
    let path = "/databases/(default)/documents/users/alice/notes/n1";
    let alice = evaluate_request(
        &ruleset,
        &ctx(Method::Get, path, Some(auth("alice", false, None))),
    );
    let bob = evaluate_request(
        &ruleset,
        &ctx(Method::Get, path, Some(auth("bob", false, None))),
    );

    assert!(matches!(alice.decision, Decision::Allow), "{alice:?}");
    assert!(
        matches!(bob.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{bob:?}"
    );
}

#[test]
fn nested_recursive_match_keeps_parent_function_environment() {
    let ruleset = parse_ruleset(
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents/{prefix=**} {\n    function decision() { return false; }\n    function gate() { return decision(); }\n    match /users/{owner=**} {\n      function decision() { return true; }\n      allow read: if gate();\n    }\n  }\n}",
    )
    .unwrap();
    let report = evaluate_request(
        &ruleset,
        &ctx(
            Method::Get,
            "/databases/(default)/documents/users/alice/profile",
            Some(auth("alice", false, None)),
        ),
    );

    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{report:?}"
    );
}

#[test]
fn storage_function_calls_resolve_in_the_definition_scope() {
    let ruleset = parse_ruleset(
        "rules_version = '2';\nservice firebase.storage {\n  function decision() { return false; }\n  function gate() { return decision(); }\n  match /b/{bucket}/o/{path=**} {\n    function decision() { return true; }\n    allow read: if gate();\n  }\n}",
    )
    .unwrap();
    let mut request = ctx(Method::Get, "/b/example/o/file.txt", None);
    request.service = RulesService::Storage;
    let report = evaluate_request(&ruleset, &request);

    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::NoMatchingAllow)),
        "{report:?}"
    );
}

#[test]
fn nested_recursive_wildcards_are_bounded_by_match_work_budget() {
    let mut source = String::from("rules_version = '2';\nservice cloud.firestore {\n");
    for index in 0..8 {
        let _ = writeln!(source, "  match /{{part{index}=**}} {{");
    }
    source.push_str("    match /segment19 { allow write; }\n");
    for _ in 0..8 {
        source.push_str("  }\n");
    }
    source.push('}');
    let ruleset = parse_ruleset(&source).unwrap();
    let path = format!(
        "/{}",
        (0..20)
            .map(|index| format!("segment{index}"))
            .collect::<Vec<_>>()
            .join("/")
    );
    let report = evaluate_request(&ruleset, &ctx(Method::Get, &path, None));

    assert!(
        matches!(
            report.decision,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "FIREEMU-RULES-MATCH-WORK",
                ..
            })
        ),
        "{report:?}"
    );
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
fn unsupported_parent_allow_cannot_be_overridden_by_a_nested_allow() {
    let src = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /a/{x} {\n      allow read: if get(/databases/$(db)/documents/b/$(x)).data.ok == true;\n      match /{rest=**} { allow read: if true; }\n    }\n  }\n}";
    let ruleset = parse_ruleset(src).unwrap();
    let report = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
    );

    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::Unsupported(_))),
        "{report:?}"
    );
}

#[test]
fn unsupported_sibling_allow_cannot_be_overridden_by_a_later_allow() {
    let src = "service cloud.firestore {\n  match /databases/{db}/documents {\n    match /a/{x} {\n      allow read: if get(/databases/$(db)/documents/b/$(x)).data.ok == true;\n    }\n    match /a/{x} { allow read: if true; }\n  }\n}";
    let ruleset = parse_ruleset(src).unwrap();
    let report = evaluate_request(
        &ruleset,
        &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
    );

    assert!(
        matches!(report.decision, Decision::Deny(DenyReason::Unsupported(_))),
        "{report:?}"
    );
}

#[test]
fn an_earlier_allow_cannot_hide_a_later_unsupported_allow() {
    for src in [
        "service cloud.firestore { match /databases/{db}/documents { match /a/{x} { allow read: if true; allow read: if get(/databases/$(db)/documents/b/$(x)).data.ok == true; } } }",
        "rules_version = '2'; service cloud.firestore { match /databases/{db}/documents { match /a/{x} { allow read: if true; match /{rest=**} { allow read: if get(/databases/$(db)/documents/b/$(x)).data.ok == true; } } } }",
        "service cloud.firestore { match /databases/{db}/documents { match /a/{x} { allow read: if true; } match /a/{x} { allow read: if get(/databases/$(db)/documents/b/$(x)).data.ok == true; } } }",
    ] {
        let ruleset = parse_ruleset(src).unwrap();
        let report = evaluate_request(
            &ruleset,
            &ctx(Method::Get, "/databases/(default)/documents/a/1", None),
        );

        assert!(
            matches!(report.decision, Decision::Deny(DenyReason::Unsupported(_))),
            "{report:?}"
        );
    }
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

    // A shallow balanced tree with more than 1,001 evaluated expressions exceeds the
    // request budget without relying on an unsafe left-nested parser tree.
    let expr = balanced_and(1_024);
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
    // Short-circuit: `false && <1,024 leaves>` costs only a few expressions.
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
    use fireemu_core_auth::claims::{ClaimValue, CustomClaims, FirebaseClaims, IdTokenClaims};
    let mut custom = CustomClaims::default();
    custom
        .insert("role", ClaimValue::String("admin".into()))
        .unwrap();
    let claims = IdTokenClaims {
        phone_number: None,
        iss: "https://securetoken.google.com/demo-app".into(),
        aud: "demo-app".into(),
        auth_time: 1,
        user_id: "u1".into(),
        sub: "u1".into(),
        iat: 1,
        exp: 3_601,
        email: Some("u1@example.com".into()),
        email_verified: true,
        display_name: Some("User One".into()),
        photo_url: Some("https://example.test/u1.png".into()),
        provider_id: None,
        firebase: FirebaseClaims {
            identities: BTreeMap::from([("email".to_owned(), vec!["u1@example.com".to_owned()])]),
            sign_in_provider: "password".into(),
            sign_in_second_factor: Some("totp".into()),
            second_factor_identifier: Some("mfa-1".into()),
            tenant: None,
            sign_in_attributes: None,
            fireemu_session_epoch: None,
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

// ------------------------------------------------------------------------------------------
// Abstract values (query proofs) and recursive wildcards
// ------------------------------------------------------------------------------------------

fn abstract_ctx(path: &str, data: Vec<(&str, RulesValue)>) -> RequestContext {
    let mut resource = BTreeMap::new();
    resource.insert(
        "data".to_owned(),
        RulesValue::PartialMap(data.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()),
    );
    resource.insert("id".to_owned(), RulesValue::Unknown);
    RequestContext {
        service: RulesService::Firestore,
        method: Method::List,
        path: path.to_owned(),
        auth: None,
        resource: Some(RulesValue::Map(resource)),
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: true,
        request_query: None,
    }
}

fn allows(rules: &str, ctx: &RequestContext) -> bool {
    let ruleset = parse_ruleset(rules).unwrap();
    matches!(evaluate_request(&ruleset, ctx).decision, Decision::Allow)
}

#[test]
fn undetermined_values_never_prove_a_condition() {
    let rules = |cond: &str| {
        format!("rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {cond}; }} }} }}")
    };
    let known = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("owner", RulesValue::String("u1".into()))],
    );
    assert!(allows(&rules("resource.data.owner == 'u1'"), &known));
    assert!(!allows(&rules("resource.data.owner == 'u2'"), &known));
    // Anything depending on an unconstrained field, the map shape, the id or the path
    // cannot be proven.
    for cond in [
        "resource.data.secret == null",
        "!('blocked' in resource.data)",
        "resource.data.keys().hasOnly(['owner'])",
        "resource.data.size() == 1",
        "resource.data.get('flag', false) == false",
        "id != 'secret'",
        "resource.id != 'secret'",
        "request.path[3] == 'notes'",
        "resource.data.other is string",
        "!(resource.data.other is string)",
    ] {
        assert!(!allows(&rules(cond), &known), "{cond} must not be provable");
    }
    // Left to right: a deciding operand ends the evaluation, an undetermined one (which may
    // be a runtime error for some document) makes the expression undetermined.
    assert!(allows(
        &rules("resource.data.owner == 'u1' || resource.data.secret == 1"),
        &known
    ));
    // An operand that decides the answer absorbs an undetermined one on either side, which
    // is both what the official runtime does with a raised operand and sound for a proof:
    // whatever the unconstrained field holds, `|| true` is true for every document it could
    // hold, and `&& false` is false for every one.
    assert!(allows(&rules("resource.data.secret == 1 || true"), &known));
    assert!(!allows(
        &rules("resource.data.secret == 1 && false"),
        &known
    ));
    assert!(allows(&rules("true || resource.data.secret == 1"), &known));
    assert!(!allows(
        &rules("resource.data.owner == 'u1' && resource.data.secret == 1"),
        &known
    ));
    assert!(!allows(
        &rules("resource.data.secret == 1 ? true : true"),
        &known
    ));
    // Containers holding an undetermined member are undetermined too.
    assert!(!allows(&rules("[resource.data.secret] != [null]"), &known));
    assert!(!allows(
        &rules("{'k': resource.data.secret} == {'k': 1}"),
        &known
    ));
    assert!(!allows(&rules("1 in [resource.data.secret]"), &known));
    // Partial lists prove membership, nothing else.
    let tags = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![(
            "tags",
            RulesValue::PartialList(vec![RulesValue::String("x".into())]),
        )],
    );
    assert!(allows(&rules("resource.data.tags.hasAny(['x'])"), &tags));
    assert!(allows(&rules("'x' in resource.data.tags"), &tags));
    assert!(allows(&rules("resource.data.tags is list"), &tags));
    for cond in [
        "resource.data.tags.size() == 1",
        "resource.data.tags.hasOnly(['x'])",
        "resource.data.tags == ['x']",
        "resource.data.tags.hasAny(['y'])",
        "resource.data.tags[0] == 'x'",
    ] {
        assert!(!allows(&rules(cond), &tags), "{cond} must not be provable");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn query_derived_numeric_arithmetic_does_not_prove_concrete_result() {
    let rules = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{d}/documents {\n    match /notes/{id} {\n      allow list: if resource.data.value / 2 == 0;\n    }\n  }\n}";
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1))],
    );
    // Firestore query equality permits a stored double 1.0 for an integer equality filter,
    // while concrete Rules arithmetic preserves the stored representation (1.0 / 2 != 0).
    assert!(!allows(rules, &query));

    let normalized_int = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1))],
    );
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if int(resource.data.value) / 2 == 0; } } }",
        &normalized_int
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if float(resource.data.value) / 2 == 0.5; } } }",
        &normalized_int
    ));
    let zero = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(0))],
    );
    for condition in [
        "1.0 / float(resource.data.value) > 0",
        "(true ? float(resource.data.value) : 0.0) / 1.0 >= 0",
    ] {
        assert!(
            !allows(
                &format!(
                    "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
                ),
                &zero
            ),
            "{condition} must remain conservative for signed zero"
        );
    }
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function normalized() { let value = resource.data.value; return float(value); } match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / normalized() > 0; } } }",
        &zero
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { function normalized() { return int(resource.data.value); } match /notes/{id} { allow list: if normalized() / 2 == 0; } } }",
        &normalized_int
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { function normalized() { let value = int(resource.data.value); return value; } match /notes/{id} { allow list: if normalized() / 2 == 0; } } }",
        &normalized_int
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function int(value) { return value; } match /databases/{d}/documents { match /notes/{id} { allow list: if int(resource.data.value) / 2 == 0; } } }",
        &normalized_int
    ));

    let minimum_int = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(i64::MIN))],
    );
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if int(resource.data.value) is int; } } }",
        &minimum_int
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function normalized() { return int(resource.data.value); } match /databases/{d}/documents { match /notes/{id} { allow list: if normalized() is int; } } }",
        &minimum_int
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if int(string(resource.data.value)) is int; } } }",
        &minimum_int
    ));

    let large_int = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1_i64 << 60))],
    );
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if int(string(resource.data.value)) / 2 == 576460752303423488; } } }",
        &large_int
    ));

    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / float(float(resource.data.value)) > 0; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function identity(value) { return value; } match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / identity(float(resource.data.value)) > 0; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / [float(resource.data.value)][0] > 0; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function normalized() { let value = float(resource.data.value); return value; } match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / normalized() > 0; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function normalized() { let value = float(resource.data.value); return 1.0 / value > 0; } match /databases/{d}/documents { match /notes/{id} { allow list: if normalized(); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function positive(value) { return 1.0 / value > 0; } match /databases/{d}/documents { match /notes/{id} { allow list: if positive(float(resource.data.value)); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function positive(value) { return 1.0 / value[0] > 0; } match /databases/{d}/documents { match /notes/{id} { allow list: if positive([float(resource.data.value)]); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function positive(value) { return 1.0 / value.zero > 0; } match /databases/{d}/documents { match /notes/{id} { allow list: if positive({'zero': float(resource.data.value)}); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / debug(float(resource.data.value)) > 0; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if 1.0 / float(string(resource.data.value)) > 0; } } }",
        &zero
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { function f(resource) { return 1.0 / resource > 0; } match /databases/{d}/documents { match /notes/{id} { allow list: if f(0.0); } } }",
        &zero
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if float(int(resource.data.value)) + 1 == 1; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if string(resource.data.value).size() + 1 == 2; } } }",
        &zero
    ));
    for condition in [
        "(true ? string(resource.data.value) : '').size() + 1 == 2",
        "[string(resource.data.value)][0].size() + 1 == 2",
        "('' + string(resource.data.value)).size() + 1 == 2",
        "[resource.data.value].join('').size() + 1 == 2",
    ] {
        assert!(
            !allows(
                &format!(
                    "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
                ),
                &zero
            ),
            "{condition} must remain conservative for representation-sensitive strings"
        );
    }
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function text() { return string(float(resource.data.value)); } match /databases/{d}/documents { match /notes/{id} { allow list: if text().size() + 1 == 2; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function text() { return string(float(resource.data.value)); } function wrapped() { return text(); } match /databases/{d}/documents { match /notes/{id} { allow list: if wrapped() == '0'; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function number() { return float(resource.data.value); } function text() { return string(number()); } match /databases/{d}/documents { match /notes/{id} { allow list: if text() == '0'; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function pick(value) { return value.n; } function check(value) { return string(pick({'n': resource.data.value})) == '0'; } match /databases/{d}/documents { match /notes/{id} { allow list: if check({'n': 'unrelated'}); } } }",
        &zero
    ));
    let known_string = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::String("abc".to_owned()))],
    );
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { function value() { return resource.data.value; } match /databases/{d}/documents { match /notes/{id} { allow list: if string(value()) == 'abc'; } } }",
        &known_string
    ));
    let list_zero = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::List(vec![RulesValue::Int(0)]))],
    );
    for condition in [
        "string(pick()) == '0'",
        "string(pick()) in ['0']",
        "{'0': true, '-0': false}[string(pick())]",
    ] {
        let list_helper_rules = format!(
            "rules_version = '2';\nservice cloud.firestore {{ function pick() {{ return resource.data.value[0]; }} match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        );
        assert!(
            !allows(&list_helper_rules, &list_zero),
            "{condition} must preserve numeric provenance through a list member"
        );
    }
    for condition in ["{'0': true, '-0': false}[text()]", "['0'].hasAny([text()])"] {
        let nested_numeric_rules = format!(
            "rules_version = '2';\nservice cloud.firestore {{ function number() {{ return float(resource.data.value); }} function text() {{ return string(number()); }} match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        );
        assert!(
            !allows(&nested_numeric_rules, &zero),
            "{condition} must preserve numeric provenance through nested wrappers"
        );
    }
    for condition in [
        "{'0': true, '-0': false}[wrapped()]",
        "['0'].hasAny([wrapped()])",
    ] {
        let wrapped_rules = format!(
            "rules_version = '2';\nservice cloud.firestore {{ function text() {{ return string(float(resource.data.value)); }} function wrapped() {{ return text(); }} match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        );
        assert!(!allows(&wrapped_rules, &zero), "{condition}");
    }
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function identity(value) { return value; } match /databases/{d}/documents { match /notes/{id} { allow list: if string(identity(float(resource.data.value))).size() + 1 == 2; } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function pick(value) { return string(value[0]).size() + 1 == 2; } match /databases/{d}/documents { match /notes/{id} { allow list: if pick([float(resource.data.value)]); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function pick(value) { return string(value.zero).size() + 1 == 2; } match /databases/{d}/documents { match /notes/{id} { allow list: if pick({'zero': float(resource.data.value)}); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function joined() { return [resource.data.value].join(''); } match /databases/{d}/documents { match /notes/{id} { allow list: if joined().size() + 1 == 2; } } }",
        &zero
    ));
    let query_list = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("tags", RulesValue::List(vec![RulesValue::Int(0)]))],
    );
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if resource.data.tags.join('').size() == 1; } } }",
        &query_list
    ));
    let mut concrete_list = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_list.resource = Some(doc(&[(
        "tags",
        RulesValue::List(vec![RulesValue::Float(-0.0)]),
    )]));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow get: if resource.data.tags.join('').size() == 2; } } }",
        &concrete_list
    ));
    let query_separator = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![
            (
                "tags",
                RulesValue::List(vec![
                    RulesValue::String("x".to_owned()),
                    RulesValue::String("y".to_owned()),
                ]),
            ),
            ("separator", RulesValue::Int(0)),
        ],
    );
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if resource.data.tags.join(string(resource.data.separator)).size() == 3; } } }",
        &query_separator
    ));
    let mut concrete_separator = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_separator.resource = Some(doc(&[
        (
            "tags",
            RulesValue::List(vec![
                RulesValue::String("x".to_owned()),
                RulesValue::String("y".to_owned()),
            ]),
        ),
        ("separator", RulesValue::Float(-0.0)),
    ]));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow get: if resource.data.tags.join(string(resource.data.separator)).size() == 4; } } }",
        &concrete_separator
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function normalized() { let value = float(resource.data.value); return string(value).size() + 1 == 2; } match /databases/{d}/documents { match /notes/{id} { allow list: if normalized(); } } }",
        &zero
    ));
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function identity(value) { return string(value).size() + 1 == 2; } match /databases/{d}/documents { match /notes/{id} { allow list: if identity(float(resource.data.value)); } } }",
        &zero
    ));
    for condition in [
        "{'0': true, '-0': false}[string(float(resource.data.value))]",
        "{'0': true, '-0': false}.get(string(float(resource.data.value)), false)",
        "string(float(resource.data.value)) in ['0']",
        "['0'].hasAny([string(float(resource.data.value))])",
        "['0', string(float(resource.data.value))].hasOnly(['0'])",
        "['0', string(float(resource.data.value))].toSet().size() == 1",
        "'0'.matches(string(float(resource.data.value)))",
        "'0'.replace(string(float(resource.data.value)), 'x') == 'x'",
        "path('/notes/{id}').bind({id: string(float(resource.data.value))}) == path('/notes/0')",
    ] {
        assert!(
            !allows(
                &format!(
                    "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
                ),
                &zero
            ),
            "{condition} must not use one numeric string representation as a query proof"
        );
    }
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { function check(resource) { return int(string(resource)) / 2 == 576460752303423488; } match /databases/{d}/documents { match /notes/{id} { allow list: if check(resource.data.value); } } }",
        &large_int
    ));
    for access in ["resource.data.value", "resource.data['value']"] {
        let shadowed_global_rules = format!(
            "rules_version = '2';\nservice cloud.firestore {{ function pick() {{ return {access}; }} function check(resource) {{ return string(pick()) == '0'; }} match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if check({{'data': {{'value': 'unrelated'}}}}); }} }} }}"
        );
        assert!(
            !allows(&shadowed_global_rules, &zero),
            "{access} must resolve global resource without caller shadowing"
        );
    }
    assert!(!allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if math.pow(float(resource.data.value), -1) > 0; } } }",
        &zero
    ));
    let empty = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::String(String::new()))],
    );
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if float(resource.data.value.size()) + 1 == 1; } } }",
        &empty
    ));

    let sized_string = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::String("abc".to_owned()))],
    );
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if string(resource.data.value).size() == 3; } } }",
        &sized_string
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { function length(value) { return string(value).size() == 1; } match /databases/{d}/documents { match /notes/{id} { allow list: if length(1); } } }",
        &sized_string
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { function shadow(value) { let value = value; let text = string(value); return text.size() == 1; } match /databases/{d}/documents { match /notes/{id} { allow list: if shadow(1); } } }",
        &sized_string
    ));
    assert!(allows(
        "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if resource.data.value.size() + 1 == 4; } } }",
        &sized_string
    ));
}

#[test]
fn query_proof_rejects_numeric_representation_sensitive_integer_builtins() {
    let rules = |condition: &str| {
        format!(
            "rules_version = '2'; service cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        )
    };
    for (field, condition) in [
        ("value", "timestamp.value(resource.data.value) is timestamp"),
        (
            "year",
            "timestamp.date(resource.data.year, 1, 1) is timestamp",
        ),
        (
            "magnitude",
            "duration.value(resource.data.magnitude, 's') is duration",
        ),
        (
            "hours",
            "duration.time(resource.data.hours, 0, 0, 0) is duration",
        ),
    ] {
        let query = abstract_ctx(
            "/databases/(default)/documents/notes/fireemu-placeholder",
            vec![(field, RulesValue::Int(1))],
        );
        assert!(
            !allows(&rules(condition), &query),
            "{condition} must not use an integer representative for an integer-only builtin"
        );
    }
    let normalized = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1))],
    );
    assert!(allows(
        &rules("timestamp.value(int(resource.data.value)) is timestamp"),
        &normalized
    ));
    assert!(allows(
        "rules_version = '2'; service cloud.firestore { function normalize(value) { return int(value); } match /databases/{d}/documents { match /notes/{id} { allow list: if timestamp.value(normalize(resource.data.value)) is timestamp; } } }",
        &normalized
    ));
    assert!(allows(
        &rules("duration.time(1, 2, 3, 4) is duration"),
        &normalized
    ));
    let aliased = "rules_version = '2'; service cloud.firestore { function identity(value) { return value; } match /databases/{d}/documents { match /notes/{id} { allow list: if timestamp.date(identity(resource.data.year), 1, 1) is timestamp; } } }";
    let aliased_query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("year", RulesValue::Int(2026))],
    );
    assert!(!allows(aliased, &aliased_query));
}

#[test]
fn query_proof_rejects_unary_negation_at_the_integer_boundary() {
    let rules = "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if (-resource.data.value) == 9223372036854775808.0; } } }";
    let float_normalized = "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if (-float(resource.data.value)) == 9223372036854775808.0; } } }";
    let helper_normalized = "rules_version = '2'; service cloud.firestore { function normalize(value) { return float(value); } match /databases/{d}/documents { match /notes/{id} { allow list: if (-normalize(resource.data.value)) == 9223372036854775808.0; } } }";
    let let_normalized = "rules_version = '2'; service cloud.firestore { function normalize(value) { let converted = float(value); return converted; } match /databases/{d}/documents { match /notes/{id} { allow list: if (-normalize(resource.data.value)) == 9223372036854775808.0; } } }";
    for value in [
        RulesValue::Int(i64::MIN),
        RulesValue::Float(-(2f64.powi(63))),
    ] {
        let query = abstract_ctx(
            "/databases/(default)/documents/notes/fireemu-placeholder",
            vec![("value", value)],
        );
        assert!(!allows(rules, &query));
        assert!(allows(float_normalized, &query));
        assert!(allows(helper_normalized, &query));
        assert!(allows(let_normalized, &query));
    }
    let identity_rules = "rules_version = '2'; service cloud.firestore { function identity(value) { return value; } match /databases/{d}/documents { match /notes/{id} { allow list: if (-identity(resource.data.value)) == 9223372036854775808.0; } } }";
    let identity_query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(i64::MIN))],
    );
    assert!(!allows(identity_rules, &identity_query));
}

#[test]
fn query_provenance_reuses_repeated_function_declarations() {
    use std::fmt::Write as _;

    let mut source = String::from("rules_version = '2';\nservice cloud.firestore {\n");
    for depth in 0..=6 {
        if depth == 0 {
            source.push_str("  function f0() { return false; }\n");
            continue;
        }
        let calls = (0..8)
            .map(|_| format!("f{}()", depth - 1))
            .collect::<Vec<_>>();
        writeln!(
            source,
            "  function f{depth}() {{ return {}; }}",
            calls.join(" || ")
        )
        .unwrap();
    }
    source.push_str(
        "  match /databases/{d}/documents { match /notes/{id} { allow list: if f6(); } }\n}",
    );
    let context = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1))],
    );
    assert!(!allows(&source, &context));
}

#[test]
fn query_numeric_source_analysis_reuses_repeated_function_dag() {
    use std::fmt::Write as _;

    let mut source = String::from("rules_version = '2';\nservice cloud.firestore {\n");
    source.push_str("  function f0() { return 0; }\n");
    for depth in 1..=6 {
        let calls = (0..8).fold(format!("f{}()", depth - 1), |nested, _| {
            format!("false ? f{}() : ({nested})", depth - 1)
        });
        writeln!(source, "  function f{depth}() {{ return {calls}; }}").unwrap();
    }
    source.push_str(
        "  match /databases/{d}/documents/notes/{id} { allow list: if string(f6()).size() == 1; }\n}",
    );
    let ctx = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(0))],
    );
    assert!(allows(&source, &ctx));
}

#[test]
fn query_provenance_cycle_does_not_cache_context_dependent_false() {
    let source = "rules_version = '2';
service cloud.firestore {
  function a() { return false ? b() : resource.data.value; }
  function b() { return a(); }
  match /databases/{d}/documents {
    match /notes/{id} {
      allow list: if a() == 1 && b() / 2 == 0;
    }
  }
}";
    let context = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1))],
    );
    // A matching integer equality filter may represent a stored double. The concrete double
    // makes the second arithmetic condition false, so the query proof must not allow it.
    assert!(!allows(source, &context));
}

#[test]
fn query_provenance_cache_preserves_short_circuit_function_graphs() {
    use std::fmt::Write as _;

    let mut source = String::from("rules_version = '2';\nservice cloud.firestore {\n");
    for depth in 0..=6 {
        if depth == 0 {
            source.push_str("  function f0() { return true; }\n");
            continue;
        }
        let calls = (0..8)
            .map(|_| format!("f{}()", depth - 1))
            .collect::<Vec<_>>();
        writeln!(
            source,
            "  function f{depth}() {{ return {}; }}",
            calls.join(" || ")
        )
        .unwrap();
    }
    source.push_str(
        "  match /databases/{d}/documents { match /notes/{id} { allow list: if f6() is bool; } }\n}",
    );
    let context = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("value", RulesValue::Int(1))],
    );
    assert!(allows(&source, &context));
}

#[test]
fn query_equality_keeps_nested_numeric_values_conservative() {
    let rules = |condition: &str| {
        format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        )
    };
    let query_value = RulesValue::List(vec![RulesValue::Int(1)]);
    let nested = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![(
            "meta",
            RulesValue::Map(BTreeMap::from([("payload".to_owned(), query_value)])),
        )],
    );

    // Firestore equality accepts the stored double as equal to the query integer, so the
    // proof cannot establish that a Rules comparison against the double is different.
    assert!(!allows(
        &rules("resource.data.meta.payload != [1.0]"),
        &nested
    ));
    assert!(!allows(
        &rules("resource.data.meta.payload == [1.0]"),
        &nested
    ));
    assert!(!allows(
        &rules("resource.data.meta.payload == [1]"),
        &nested
    ));
    assert!(!allows(
        &rules("resource.data.meta.payload != [1]"),
        &nested
    ));
    assert!(!allows(
        &rules("resource.data.meta.payload in [[1.0]]"),
        &nested
    ));
    assert!(!allows(
        &rules("!(resource.data.meta.payload in [[1.0]])"),
        &nested
    ));
    // The query does not preserve integer versus double representation, including through
    // an index into a nested list.
    assert!(!allows(
        &rules("resource.data.meta.payload[0] is int"),
        &nested
    ));
    assert!(allows(
        &rules("resource.data.meta.payload[0] is number"),
        &nested
    ));

    let nested_map_payload =
        RulesValue::Map(BTreeMap::from([("score".to_owned(), RulesValue::Int(1))]));
    let nested_map_meta =
        RulesValue::Map(BTreeMap::from([("payload".to_owned(), nested_map_payload)]));
    let nested_map = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("meta", nested_map_meta)],
    );
    assert!(!allows(
        &rules("resource.data.meta != { payload: { score: 1.0 } }"),
        &nested_map
    ));
}

#[test]
fn query_map_diff_changed_keys_does_not_prove_numeric_nested_difference() {
    let rules = "rules_version = '2'; service cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if timestamp.date(resource.data.before.diff(resource.data.after).changedKeys().size(), 1, 1) is timestamp; } } }";
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![
            (
                "before",
                RulesValue::Map(BTreeMap::from([(
                    "nested".to_owned(),
                    RulesValue::Map(BTreeMap::from([(
                        "value".to_owned(),
                        RulesValue::Float(1.0),
                    )])),
                )])),
            ),
            (
                "after",
                RulesValue::Map(BTreeMap::from([(
                    "nested".to_owned(),
                    RulesValue::Map(BTreeMap::from([("value".to_owned(), RulesValue::Int(1))])),
                )])),
            ),
        ],
    );
    assert!(!allows(rules, &query));
}

#[test]
fn query_equality_provenance_survives_function_and_let_aliases() {
    let rules = |condition: &str| {
        format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ function getter() {{ return resource.data.meta.payload; }} function gate(value) {{ let alias = value; return {condition}; }} match /notes/{{id}} {{ allow list: if gate(getter()); }} }} }}"
        )
    };
    let payload = RulesValue::List(vec![RulesValue::Int(1)]);
    let meta = RulesValue::Map(BTreeMap::from([("payload".to_owned(), payload)]));
    let nested = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("meta", meta)],
    );

    assert!(!allows(&rules("alias != [1.0]"), &nested));
    assert!(!allows(&rules("alias[0] is int"), &nested));
}

#[test]
fn query_provenance_uses_each_function_declaration_scope() {
    let rules = "rules_version = '2';
service cloud.firestore {
  function source() { return resource.data.meta.payload; }
  function getter() { return source(); }
  match /databases/{d}/documents {
    match /notes/{id} {
      function source() { return [1]; }
      allow read: if getter() != [1.0];
    }
  }
}";
    let payload = RulesValue::List(vec![RulesValue::Int(1)]);
    let meta = RulesValue::Map(BTreeMap::from([("payload".to_owned(), payload)]));
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("meta", meta)],
    );
    assert!(!allows(rules, &query));

    let mut concrete = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete.resource = Some(doc(&[(
        "meta",
        RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::List(vec![RulesValue::Float(1.0)]),
        )])),
    )]));
    assert!(!allows(rules, &concrete));
}

#[test]
fn query_provenance_includes_resource_derived_index_expressions() {
    let rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{d}/documents {
    match /notes/{id} {
      allow read: if [1, 1.0][resource.data.index] is int;
    }
  }
}";
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("index", RulesValue::Int(0))],
    );
    assert!(!allows(rules, &query));

    let function_rules = "rules_version = '2';
service cloud.firestore {
  function pick() { return [1, 1.0][resource.data.index] is int; }
  match /databases/{d}/documents {
    match /notes/{id} { allow read: if pick(); }
  }
}";
    assert!(!allows(function_rules, &query));

    let mut concrete = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete.resource = Some(doc(&[("index", RulesValue::Int(1))]));
    assert!(!allows(rules, &concrete));
}

#[test]
fn query_provenance_includes_resource_derived_document_paths() {
    use fireemu_core_rules::eval::evaluate_request_with;

    let rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow read: if get(/databases/$(database)/documents/other/$(resource.data.target)).data.payload == [1.0];
    }
  }
}";
    let ruleset = parse_ruleset(rules).unwrap();
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("target", RulesValue::String("a".to_owned()))],
    );
    let access = MapAccess(BTreeMap::from([(
        "databases/(default)/documents/other/a".to_owned(),
        resource(vec![(
            "payload",
            RulesValue::List(vec![RulesValue::Float(1.0)]),
        )]),
    )]));
    assert!(matches!(
        evaluate_request_with(&ruleset, &query, Some(&access)).decision,
        Decision::Deny(_)
    ));

    let mut concrete = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete.resource = Some(doc(&[("target", RulesValue::String("a".to_owned()))]));
    assert!(matches!(
        evaluate_request_with(&ruleset, &concrete, Some(&access)).decision,
        Decision::Allow
    ));

    let function_rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function check() {
      return get(/databases/$(database)/documents/other/$(resource.data.target)).data.payload == [1.0];
    }
    match /notes/{id} { allow read: if check(); }
  }
}";
    let function_ruleset = parse_ruleset(function_rules).unwrap();
    assert!(matches!(
        evaluate_request_with(&function_ruleset, &query, Some(&access)).decision,
        Decision::Deny(_)
    ));
}

#[test]
fn query_index_and_slice_bounds_reject_numeric_representation_variance() {
    let index_rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{d}/documents {
    match /notes/{id} {
      allow read: if [true][resource.data.index] == true;
    }
  }
}";
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("index", RulesValue::Int(0))],
    );
    assert!(!allows(index_rules, &query));

    let mut concrete_float = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_float.resource = Some(doc(&[("index", RulesValue::Float(0.0))]));
    assert!(!allows(index_rules, &concrete_float));

    let mut concrete_int = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_int.resource = Some(doc(&[("index", RulesValue::Int(0))]));
    assert!(allows(index_rules, &concrete_int));

    let slice_rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{d}/documents {
    match /notes/{id} {
      allow read: if [true, false][resource.data.start:resource.data.end].size() == 1;
    }
  }
}";
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("start", RulesValue::Int(0)), ("end", RulesValue::Int(1))],
    );
    assert!(!allows(slice_rules, &query));

    let mut concrete_float = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_float.resource = Some(doc(&[
        ("start", RulesValue::Float(0.0)),
        ("end", RulesValue::Int(1)),
    ]));
    assert!(!allows(slice_rules, &concrete_float));

    let mut concrete_int = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_int.resource = Some(doc(&[
        ("start", RulesValue::Int(0)),
        ("end", RulesValue::Int(1)),
    ]));
    assert!(allows(slice_rules, &concrete_int));
}

#[test]
fn query_paths_reject_numeric_bindings_before_interpolation() {
    use fireemu_core_rules::eval::evaluate_request_with;

    let rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow read: if exists(/databases/$(database)/documents/other/$(resource.data.target));
    }
  }
}";
    let ruleset = parse_ruleset(rules).unwrap();
    let access = MapAccess(BTreeMap::from([(
        "databases/(default)/documents/other/1".to_owned(),
        resource(vec![]),
    )]));
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("target", RulesValue::Int(1))],
    );
    assert!(matches!(
        evaluate_request_with(&ruleset, &query, Some(&access)).decision,
        Decision::Deny(_)
    ));

    let mut concrete_float = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_float.resource = Some(doc(&[("target", RulesValue::Float(1.0))]));
    assert!(matches!(
        evaluate_request_with(&ruleset, &concrete_float, Some(&access)).decision,
        Decision::Deny(_)
    ));

    let mut concrete_string = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_string.resource = Some(doc(&[("target", RulesValue::String("1".to_owned()))]));
    assert!(matches!(
        evaluate_request_with(&ruleset, &concrete_string, Some(&access)).decision,
        Decision::Allow
    ));
}

#[test]
fn query_path_bind_rejects_numeric_aliases_before_interpolation() {
    let rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{d}/documents {
    function check() {
      let target = resource.data.target;
      return path('/other/{id}').bind({id: target}) == path('/other/1');
    }
    match /notes/{id} { allow read: if check(); }
  }
}";
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("target", RulesValue::Int(1))],
    );
    assert!(!allows(rules, &query));

    let mut concrete_float = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_float.resource = Some(doc(&[("target", RulesValue::Float(1.0))]));
    assert!(!allows(rules, &concrete_float));

    let mut concrete_int = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete_int.resource = Some(doc(&[("target", RulesValue::Int(1))]));
    assert!(allows(rules, &concrete_int));
}

#[test]
fn partial_query_list_membership_does_not_assume_nested_numeric_representation() {
    let rules = |condition: &str| {
        format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        )
    };
    let tag = RulesValue::Map(BTreeMap::from([("score".to_owned(), RulesValue::Int(1))]));
    let tags = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("tags", RulesValue::PartialList(vec![tag]))],
    );

    assert!(!allows(
        &rules("{'score': 1.0} in resource.data.tags"),
        &tags
    ));
}

#[test]
fn query_derived_list_and_set_membership_methods_remain_conservative() {
    let rules = |condition: &str| {
        format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow read: if {condition}; }} }} }}"
        )
    };
    let same_tag = RulesValue::Map(BTreeMap::from([(
        "score".to_owned(),
        RulesValue::String("same".to_owned()),
    )]));
    let same = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("tags", RulesValue::List(vec![same_tag]))],
    );
    for condition in [
        "resource.data.tags == [{score: 'same'}]",
        "resource.data.tags.hasAny([{score: 'same'}])",
        "resource.data.tags.hasAll([{score: 'same'}])",
        "resource.data.tags.hasOnly([{score: 'same'}])",
        "resource.data.tags.toSet().hasAny([{score: 'same'}])",
        "resource.data.tags.toSet().hasAll([{score: 'same'}])",
        "resource.data.tags.toSet().hasOnly([{score: 'same'}])",
    ] {
        assert!(allows(&rules(condition), &same), "condition: {condition}");
    }

    let query_tag = RulesValue::Map(BTreeMap::from([("score".to_owned(), RulesValue::Int(1))]));
    let query = abstract_ctx(
        "/databases/(default)/documents/notes/fireemu-placeholder",
        vec![("tags", RulesValue::List(vec![query_tag]))],
    );
    for condition in [
        "resource.data.tags == [{score: 1.0}]",
        "!(resource.data.tags == [{score: 1.0}])",
        "resource.data.tags != [{score: 1.0}]",
        "resource.data.tags.hasAny([{score: 1}])",
        "!resource.data.tags.hasAny([{score: 1.0}])",
        "resource.data.tags.hasAll([{score: 1}])",
        "!resource.data.tags.hasAll([{score: 1.0}])",
        "resource.data.tags.hasOnly([{score: 1}])",
        "!resource.data.tags.hasOnly([{score: 1.0}])",
        "resource.data.tags.toSet().hasAny([{score: 1}])",
        "!resource.data.tags.toSet().hasAny([{score: 1.0}])",
        "resource.data.tags.removeAll([{score: 1}]).size() == 0",
        "resource.data.tags.toSet().difference([{score: 1}].toSet()).size() == 0",
    ] {
        assert!(!allows(&rules(condition), &query), "condition: {condition}");
    }

    let mut concrete = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    concrete.resource = Some(doc(&[(
        "tags",
        RulesValue::List(vec![RulesValue::Map(BTreeMap::from([(
            "score".to_owned(),
            RulesValue::Float(1.0),
        )]))]),
    )]));
    for condition in [
        "resource.data.tags != [{score: 1.0}]",
        "resource.data.tags.hasAny([{score: 1}])",
        "!resource.data.tags.hasAny([{score: 1.0}])",
        "resource.data.tags.hasAll([{score: 1}])",
        "!resource.data.tags.hasAll([{score: 1.0}])",
        "resource.data.tags.hasOnly([{score: 1}])",
        "!resource.data.tags.hasOnly([{score: 1.0}])",
        "resource.data.tags.removeAll([{score: 1}]).size() == 0",
        "resource.data.tags.toSet().difference([{score: 1}].toSet()).size() == 0",
    ] {
        assert!(
            !allows(&rules(condition), &concrete),
            "condition: {condition}"
        );
    }
}

#[test]
fn recursive_wildcards_backtrack_and_bind_undetermined_captures_in_proofs() {
    let group = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{path=**}/reviews/{r} { allow list: if true; } } }";
    for path in [
        "/databases/(default)/documents/reviews/fireemu-placeholder",
        "/databases/(default)/documents/posts/fireemu-placeholder/reviews/fireemu-placeholder",
    ] {
        assert!(allows(group, &abstract_ctx(path, vec![])), "{path}");
    }
    // Version 1: `**` needs at least one segment.
    let v1 = "service cloud.firestore { match /databases/{d}/documents { match /{path=**}/reviews/{r} { allow list: if true; } } }";
    assert!(!allows(
        v1,
        &abstract_ctx(
            "/databases/(default)/documents/reviews/fireemu-placeholder",
            vec![]
        )
    ));
    assert!(allows(
        v1,
        &abstract_ctx(
            "/databases/(default)/documents/a/reviews/fireemu-placeholder",
            vec![]
        )
    ));
    // A capture cannot decide a proof, and a rule relying on it is not provable.
    let by_capture = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow list: if id == 'x'; } } }";
    assert!(!allows(
        by_capture,
        &abstract_ctx(
            "/databases/(default)/documents/notes/fireemu-placeholder",
            vec![]
        )
    ));
    // A literal segment never equals the abstract id, and the "any prefix" marker is only
    // covered by a recursive wildcard.
    let literal = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/fireemu-placeholder { allow list: if true; } } }";
    assert!(!allows(
        literal,
        &abstract_ctx(
            "/databases/(default)/documents/notes/fireemu-placeholder",
            vec![]
        )
    ));
    let fixed_depths = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /reviews/{r} { allow list: if true; } match /{a}/{b}/reviews/{r} { allow list: if true; } } }";
    let group_path =
        "/databases/(default)/documents/fireemu-any-prefix/fireemu-any-prefix/reviews/fireemu-placeholder";
    assert!(!allows(fixed_depths, &abstract_ctx(group_path, vec![])));
    assert!(allows(group, &abstract_ctx(group_path, vec![])));
}

// ------------------------------------------------------------------------------------------
// get() / exists() document access
// ------------------------------------------------------------------------------------------

struct MapAccess(BTreeMap<String, RulesValue>);

impl fireemu_core_rules::eval::DocumentAccess for MapAccess {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        self.0.get(&segments.join("/")).cloned()
    }
}

#[test]
fn collection_group_recursive_capture_does_not_expose_the_abstract_prefix() {
    let rules = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{path=**}/reviews/{id} { allow list: if path == path('/fireemu-any-prefix/fireemu-any-prefix'); } } }";
    let query = abstract_ctx(
        "/databases/(default)/documents/fireemu-any-prefix/fireemu-any-prefix/reviews/fireemu-placeholder",
        vec![],
    );

    // The collection-group prefix is a sentinel for an arbitrary ancestor chain. A recursive
    // capture that consumes it must remain undetermined, just like a capture of the document id.
    assert!(!allows(rules, &query));
}

fn resource(fields: Vec<(&str, RulesValue)>) -> RulesValue {
    let mut m = BTreeMap::new();
    m.insert(
        "data".to_owned(),
        RulesValue::Map(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()),
    );
    RulesValue::Map(m)
}

#[test]
fn query_proof_rejects_numeric_path_bindings_for_document_access() {
    use fireemu_core_rules::eval::evaluate_request_with;

    let access = MapAccess(BTreeMap::from([(
        "databases/(default)/documents/gates/0".to_owned(),
        resource(vec![("ok", RulesValue::Bool(true))]),
    )]));
    let query_context = abstract_ctx(
        "/databases/(default)/documents/notes/query",
        vec![("value", RulesValue::Int(0))],
    );
    let concrete_context = RequestContext {
        service: RulesService::Firestore,
        method: Method::List,
        path: "/databases/(default)/documents/notes/concrete".to_owned(),
        auth: None,
        resource: Some(resource(vec![("value", RulesValue::Float(-0.0))])),
        request_resource: None,
        time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
        abstract_path: false,
        request_query: None,
    };
    let path = "path('/databases/(default)/documents/gates/{id}').bind({'id': string(float(resource.data.value))})";
    for condition in [
        format!("exists({path})"),
        format!("get({path}).data.ok == true"),
        format!("firestore.exists({path})"),
        format!("firestore.get({path}).data.ok == true"),
    ] {
        let rules = format!(
            "rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /notes/{{id}} {{ allow list: if {condition}; }} }} }}"
        );
        let ruleset = parse_ruleset(&rules).unwrap();
        let query_decision =
            evaluate_request_with(&ruleset, &query_context, Some(&access)).decision;
        assert!(
            !matches!(query_decision, Decision::Allow),
            "{condition} must not authorize from one numeric path representation"
        );
        let concrete_decision =
            evaluate_request_with(&ruleset, &concrete_context, Some(&access)).decision;
        assert!(
            !matches!(concrete_decision, Decision::Allow),
            "{condition} should deny the concrete negative-zero path"
        );
    }
}

#[test]
fn get_and_exists_read_other_documents_within_the_access_budget() {
    use fireemu_core_rules::eval::evaluate_request_with;
    let rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /admin/{id} {
      allow read: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }
    match /guarded/{id} {
      allow read: if exists(/databases/$(database)/documents/flags/open);
    }
    match /costly/{id} {
      allow read: if get(/databases/$(database)/documents/a/1).data.v == 1
                  && get(/databases/$(database)/documents/a/1).data.v == 1
                  && exists(/databases/$(database)/documents/a/2)
                  && exists(/databases/$(database)/documents/a/3)
                  && exists(/databases/$(database)/documents/a/4)
                  && exists(/databases/$(database)/documents/a/5)
                  && exists(/databases/$(database)/documents/a/6)
                  && exists(/databases/$(database)/documents/a/7)
                  && exists(/databases/$(database)/documents/a/8)
                  && exists(/databases/$(database)/documents/a/9)
                  && exists(/databases/$(database)/documents/a/10)
                  && exists(/databases/$(database)/documents/a/11);
    }
  }
}";
    let ruleset = parse_ruleset(rules).unwrap();
    let mut docs = BTreeMap::new();
    docs.insert(
        "databases/(default)/documents/users/u1".to_owned(),
        resource(vec![("role", RulesValue::String("admin".into()))]),
    );
    docs.insert(
        "databases/(default)/documents/a/1".to_owned(),
        resource(vec![("v", RulesValue::Int(1))]),
    );
    for n in 2..=11 {
        docs.insert(
            format!("databases/(default)/documents/a/{n}"),
            resource(vec![]),
        );
    }
    let access = MapAccess(docs);
    let ctx = |path: &str, uid: &str| RequestContext {
        service: RulesService::Firestore,
        method: Method::Get,
        path: path.to_owned(),
        auth: Some(AuthContext {
            uid: uid.to_owned(),
            token: BTreeMap::new(),
        }),
        resource: Some(resource(vec![])),
        request_resource: None,
        time_unix_nanos: 0,
        abstract_path: false,
        request_query: None,
    };
    let admin = ctx("/databases/(default)/documents/admin/x", "u1");
    assert!(matches!(
        evaluate_request_with(&ruleset, &admin, Some(&access)).decision,
        Decision::Allow
    ));
    let stranger = ctx("/databases/(default)/documents/admin/x", "u2");
    assert!(matches!(
        evaluate_request_with(&ruleset, &stranger, Some(&access)).decision,
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
    // Without an access provider, document reads fail closed as unsupported.
    assert!(matches!(
        evaluate_request(&ruleset, &admin).decision,
        Decision::Deny(DenyReason::Unsupported(_))
    ));
    let guarded = ctx("/databases/(default)/documents/guarded/x", "u1");
    assert!(matches!(
        evaluate_request_with(&ruleset, &guarded, Some(&access)).decision,
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
    // Eleven distinct documents exceed RULES-DOC-ACCESS-SINGLE (10); the repeated path counts
    // once.
    let costly = ctx("/databases/(default)/documents/costly/x", "u1");
    assert!(matches!(
        evaluate_request_with(&ruleset, &costly, Some(&access)).decision,
        Decision::Deny(DenyReason::BudgetExceeded {
            limit_id: "RULES-DOC-ACCESS-SINGLE",
            current: 11,
            maximum: 10
        })
    ));
}

#[test]
fn function_let_bindings_are_lazy_across_short_circuit_branches() {
    let rules = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function mayRead() {
      let primary = resource.data.primaryId;
      let optional = resource.data.optionalId;
      let members = resource.data.members;
      return primary == request.auth.uid ||
             optional == request.auth.uid ||
             request.auth.uid in members;
    }
    match /records/{id} {
      allow read: if mayRead();
    }
  }
}
";
    let ruleset = parse_ruleset(rules).unwrap();
    let members = |uids: &[&str]| {
        RulesValue::Map(
            uids.iter()
                .map(|uid| ((*uid).to_owned(), RulesValue::Bool(true)))
                .collect(),
        )
    };
    let decide = |primary: &str, member_uids: &[&str]| {
        let mut request = ctx(
            Method::Get,
            "/databases/(default)/documents/records/one",
            Some(auth("alice", false, None)),
        );
        request.resource = Some(resource(vec![
            ("primaryId", RulesValue::String(primary.to_owned())),
            ("members", members(member_uids)),
        ]));
        evaluate_request(&ruleset, &request).decision
    };

    assert!(matches!(decide("alice", &[]), Decision::Allow));
    assert!(matches!(decide("other", &["alice"]), Decision::Allow));
    assert!(matches!(
        decide("other", &["someone-else"]),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
}

#[test]
fn an_unused_lazy_let_does_not_trigger_unsupported_document_access() {
    let rules = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function alwaysTrue() {
      let unused = get(/databases/$(database)/documents/other/missing);
      return true;
    }
    match /records/{id} {
      allow read: if alwaysTrue();
    }
  }
}
";
    let ruleset = parse_ruleset(rules).unwrap();
    let request = ctx(
        Method::Get,
        "/databases/(default)/documents/records/one",
        None,
    );
    assert!(matches!(
        evaluate_request(&ruleset, &request).decision,
        Decision::Allow
    ));
}

#[test]
fn string_matches_and_replace_use_the_regex_engine() {
    let rules = "rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /images/{file} {
      allow write: if request.resource.contentType.matches('image/.*')
                   && file.matches('[^/]+\\\\.(png|jpg)')
                   && file.replace('\\\\.png$', '') != 'forbidden';
    }
  }
}";
    let ruleset = parse_ruleset(rules).unwrap();
    let mut incoming = BTreeMap::new();
    incoming.insert(
        "contentType".to_owned(),
        RulesValue::String("image/png".into()),
    );
    let ctx = |file: &str, ct: &str| {
        let mut incoming = incoming.clone();
        incoming.insert("contentType".to_owned(), RulesValue::String(ct.into()));
        RequestContext {
            service: fireemu_core_rules::eval::RulesService::Storage,
            method: Method::Create,
            path: format!("/b/demo/o/images/{file}"),
            auth: None,
            resource: None,
            request_resource: Some(RulesValue::Map(incoming)),
            time_unix_nanos: 0,
            abstract_path: false,
            request_query: None,
        }
    };
    let allowed = evaluate_request(&ruleset, &ctx("cat.png", "image/png"));
    assert!(matches!(allowed.decision, Decision::Allow));
    assert_eq!(allowed.regex.runtime_compiles, 0, "{allowed:?}");
    assert_eq!(allowed.regex.peak_cache_entries, 0, "{allowed:?}");
    assert!(matches!(
        evaluate_request(&ruleset, &ctx("cat.png", "text/plain")).decision,
        Decision::Deny(_)
    ));
    assert!(matches!(
        evaluate_request(&ruleset, &ctx("cat.gif", "image/gif")).decision,
        Decision::Deny(_)
    ));
    assert!(matches!(
        evaluate_request(&ruleset, &ctx("forbidden.png", "image/png")).decision,
        Decision::Deny(_)
    ));
}

#[test]
fn dynamic_regex_patterns_are_compiled_once_per_evaluation() {
    let ruleset = parse_ruleset(
        r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if 'aaa'.matches(resource.data.pattern)
                 && 'aaa'.matches(resource.data.pattern)
                 && 'aaa'.matches(resource.data.pattern);
    }
  }
}

",
    )
    .unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[("pattern", RulesValue::String("a+".to_owned()))]));

    let first = evaluate_request(&ruleset, &request);
    assert!(matches!(first.decision, Decision::Allow), "{first:?}");
    assert_eq!(first.regex.runtime_compiles, 1, "{first:?}");
    assert_eq!(first.regex.cache_hits, 2, "{first:?}");
    assert_eq!(first.regex.peak_cache_entries, 1, "{first:?}");

    let second = evaluate_request(&ruleset, &request);
    assert_eq!(second.regex.runtime_compiles, 1, "{second:?}");
    assert_eq!(second.regex.cache_hits, 2, "{second:?}");
    assert_eq!(second.regex.peak_cache_entries, 1, "{second:?}");
}

#[test]
fn dynamic_regex_cache_has_a_request_local_entry_cap() {
    let conditions = (0..17)
        .map(|index| format!("'a'.matches(resource.data.patterns.p{index})"))
        .chain(["'a'.matches(resource.data.patterns.p0)".to_owned()])
        .collect::<Vec<_>>()
        .join(" && ");
    let ruleset = parse_ruleset(&format!(
        "rules_version = '2'; service cloud.firestore {{ match /databases/{{database}}/documents {{ match /notes/{{id}} {{ allow get: if {conditions}; }} }} }}"
    ))
    .unwrap();
    let patterns = (0..17)
        .map(|index| {
            (
                format!("p{index}"),
                RulesValue::String(format!("a{{1,{}}}", index + 1)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[("patterns", RulesValue::Map(patterns))]));

    let report = evaluate_request(&ruleset, &request);
    assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    assert_eq!(report.regex.runtime_compiles, 17, "{report:?}");
    assert_eq!(report.regex.cache_hits, 1, "{report:?}");
    assert_eq!(report.regex.peak_cache_entries, 16, "{report:?}");
}

#[test]
fn owned_evaluation_projects_scalar_members_without_cloning_large_containers() {
    let ruleset = parse_ruleset(
        "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /notes/{id} { allow get: if resource.data.a == 1 && resource.data.b == 2 && resource.data.c == 3 && resource.data.d == 4 && resource.data.e == 5; } } }",
    )
    .unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[
        ("a", RulesValue::Int(1)),
        ("b", RulesValue::Int(2)),
        ("c", RulesValue::Int(3)),
        ("d", RulesValue::Int(4)),
        ("e", RulesValue::Int(5)),
        ("unrelated", RulesValue::String("x".repeat(500 * 1024))),
    ]));

    let (report, coverage) = evaluate_request_traced_owned(&ruleset, request, None);

    assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    assert_eq!(report.projected_member_reads, 5, "{report:?}");
    assert!(!coverage.is_empty());

    let incoming_ruleset = parse_ruleset(
        "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /notes/{id} { allow create: if request.resource.data.a == 1 && request.resource.data.b == 2; } } }",
    )
    .unwrap();
    let mut incoming = ctx(
        Method::Create,
        "/databases/(default)/documents/notes/n2",
        None,
    );
    incoming.request_resource = Some(doc(&[
        ("a", RulesValue::Int(1)),
        ("b", RulesValue::Int(2)),
        ("unrelated", RulesValue::String("x".repeat(500 * 1024))),
    ]));
    let (incoming_report, _) = evaluate_request_traced_owned(&incoming_ruleset, incoming, None);
    assert!(
        matches!(incoming_report.decision, Decision::Allow),
        "{incoming_report:?}"
    );
    assert_eq!(incoming_report.projected_member_reads, 2);
}

#[test]
fn scalar_projection_respects_request_and_resource_parameter_shadowing() {
    let ruleset = parse_ruleset(
        "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { function requestAllows(request) { return request.auth.uid == 'shadow'; } function resourceAllows(resource) { return resource.data.ok == true; } match /notes/{id} { allow get: if requestAllows({'auth': {'uid': 'shadow'}}) && resourceAllows({'data': {'ok': true}}); } } }",
    )
    .unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[("ok", RulesValue::Bool(false))]));

    let report = evaluate_request(&ruleset, &request);

    assert!(matches!(report.decision, Decision::Allow), "{report:?}");
    assert_eq!(report.projected_member_reads, 0, "{report:?}");
}

#[test]
fn linear_regex_repeats_decide_normally_in_rules() {
    let rules = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /messages/{id} {
      allow create: if request.resource.data.content.matches('^(?:[\\t\\n\\r]|[^\\\\p{Cc}])*$');
    }
  }
}";
    let ruleset = parse_ruleset(rules).unwrap();
    let decide = |content: String| {
        let mut request = ctx(
            Method::Create,
            "/databases/(default)/documents/messages/m1",
            None,
        );
        request.request_resource = Some(doc(&[("content", RulesValue::String(content))]));
        evaluate_request(&ruleset, &request).decision
    };

    assert!(matches!(decide("a".repeat(3_000)), Decision::Allow));
    assert!(matches!(decide("a\tb\nc\r".to_owned()), Decision::Allow));
    assert!(matches!(
        decide("ok\u{0007}no".to_owned()),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
}

#[test]
fn range_values_decide_comparisons_only_when_every_member_agrees() {
    use fireemu_core_rules::value::{RangeBound, ValueRange};
    let rules = |cond: &str| {
        format!("rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /people/{{id}} {{ allow list: if {cond}; }} }} }}")
    };
    let bound = |v: i64, inclusive: bool| {
        Some(RangeBound {
            value: Box::new(RulesValue::Int(v)),
            inclusive,
        })
    };
    let ctx = |lower: Option<RangeBound>, upper: Option<RangeBound>| {
        abstract_ctx(
            "/databases/(default)/documents/people/fireemu-placeholder",
            vec![("age", RulesValue::Range(ValueRange { lower, upper }))],
        )
    };
    // age >= 18 (from the query) proves the same and weaker bounds, not stronger ones.
    let adults = ctx(bound(18, true), None);
    for provable in [
        "resource.data.age >= 18",
        "resource.data.age > 17",
        "resource.data.age >= 10",
        "18 <= resource.data.age",
        "resource.data.age != 5",
        "resource.data.age is number",
        "!(resource.data.age < 18)",
        "resource.data.age != 'x'",
    ] {
        assert!(allows(&rules(provable), &adults), "{provable}");
    }
    for unprovable in [
        "resource.data.age > 18",
        "resource.data.age >= 21",
        "resource.data.age < 65",
        "resource.data.age == 18",
        "resource.data.age is int",
        "resource.data.age + 1 > 18",
        "resource.data.age == 'x' || resource.data.age > 18",
    ] {
        assert!(!allows(&rules(unprovable), &adults), "{unprovable}");
    }
    // A definite false stays false (an `||` with it does not become undetermined).
    assert!(!allows(&rules("resource.data.age < 10"), &adults));
    assert!(allows(&rules("resource.data.age < 10 || true"), &adults));
    // Exclusive bounds: age > 18 does not prove age >= 18 is false, but proves > 18.
    let over = ctx(bound(18, false), None);
    assert!(allows(&rules("resource.data.age > 18"), &over));
    assert!(allows(&rules("resource.data.age >= 18"), &over));
    assert!(
        !allows(&rules("resource.data.age >= 19"), &over),
        "18.5 is a member"
    );
    // Both ends: 18 <= age < 65.
    let working = ctx(bound(18, true), bound(65, false));
    assert!(allows(
        &rules("resource.data.age >= 18 && resource.data.age < 65"),
        &working
    ));
    assert!(allows(&rules("resource.data.age <= 65"), &working));
    assert!(
        !allows(&rules("resource.data.age <= 64"), &working),
        "64.5 is a member"
    );
    assert!(allows(&rules("resource.data.age != 65"), &working));
    // A pinned range (18 <= age <= 18) is the value itself.
    let pinned = ctx(bound(18, true), bound(18, true));
    assert!(allows(&rules("resource.data.age == 18"), &pinned));
    // Comparing a number range with a string is an error for every member: the allow fails.
    assert!(!allows(&rules("resource.data.age > 'a'"), &adults));
    // request.query outside a list request is undetermined; on a list it is concrete.
    let mut limited = ctx(bound(18, true), None);
    let mut q = BTreeMap::new();
    q.insert("limit".to_owned(), RulesValue::Int(10));
    q.insert("offset".to_owned(), RulesValue::Int(0));
    q.insert("orderBy".to_owned(), RulesValue::Unknown);
    limited.request_query = Some(RulesValue::Map(q));
    assert!(allows(&rules("request.query.limit <= 10"), &limited));
    assert!(!allows(&rules("request.query.limit <= 5"), &limited));
    assert!(!allows(&rules("request.query.orderBy == 'age'"), &limited));
    assert!(!allows(&rules("request.query.limit <= 10"), &adults));
    // A range inside an exact list is still undetermined for the list methods (a negated
    // hasAny must not become a proof), and so is an undetermined argument.
    for unprovable in [
        "![resource.data.age].hasAny([18])",
        "![resource.data.age].hasAll([18])",
        "[resource.data.age].hasOnly([18])",
        "!([1, 2].hasAny([resource.data.age]))",
        "[resource.data.age].size() == 1",
    ] {
        assert!(!allows(&rules(unprovable), &adults), "{unprovable}");
    }
}

#[test]
fn integers_and_doubles_compare_exactly_beyond_2_to_the_53() {
    use fireemu_core_rules::value::{RangeBound, ValueRange};
    let rules = |cond: &str| {
        format!("rules_version = '2';\nservice cloud.firestore {{ match /databases/{{d}}/documents {{ match /big/{{id}} {{ allow list: if {cond}; }} }} }}")
    };
    // 2^53 as a double is exactly 9007199254740992; 9007199254740993 is not representable.
    let at_2_53 = abstract_ctx(
        "/databases/(default)/documents/big/fireemu-placeholder",
        vec![(
            "n",
            RulesValue::Range(ValueRange {
                lower: Some(RangeBound {
                    value: Box::new(RulesValue::Float(9_007_199_254_740_992.0)),
                    inclusive: true,
                }),
                upper: None,
            }),
        )],
    );
    assert!(allows(
        &rules("resource.data.n >= 9007199254740992"),
        &at_2_53
    ));
    assert!(
        !allows(&rules("resource.data.n >= 9007199254740993"), &at_2_53),
        "9007199254740992 is a member and is below the integer bound"
    );
    assert!(!allows(
        &rules("resource.data.n == 9007199254740993"),
        &at_2_53
    ));
    let exact = abstract_ctx(
        "/databases/(default)/documents/big/fireemu-placeholder",
        vec![("n", RulesValue::Int(9_007_199_254_740_993))],
    );
    assert!(!allows(
        &rules("resource.data.n == 9007199254740992.0"),
        &exact
    ));
    assert!(allows(
        &rules("resource.data.n > 9007199254740992.0"),
        &exact
    ));
    assert!(allows(
        &rules("resource.data.n != 9007199254740992.0"),
        &exact
    ));
    let extreme = abstract_ctx(
        "/databases/(default)/documents/big/fireemu-placeholder",
        vec![("n", RulesValue::Int(i64::MAX))],
    );
    assert!(allows(
        &rules("resource.data.n < 9223372036854775808.0"),
        &extreme
    ));
    assert!(allows(
        &rules("resource.data.n > -9223372036854775808.0"),
        &extreme
    ));
}

#[test]
fn firestore_request_shape_distinguishes_missing_members_from_null() {
    let request = ctx(
        Method::Get,
        "/databases/(default)/documents/notes/one",
        None,
    );
    let decision = |condition: &str| {
        let source = format!(
            "rules_version = '2'; service cloud.firestore {{ match /databases/{{database}}/documents/notes/{{id}} {{ allow get: if {condition}; }} }}"
        );
        evaluate_request(&parse_ruleset(&source).unwrap(), &request).decision
    };

    // A missing request member is an evaluation error. It must not behave like null.
    assert!(matches!(
        decision("request.resource == null"),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
    assert!(matches!(
        decision("request.query == null"),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
    // A missing member must not be materialized as a boolean false either. This
    // control would allow if the evaluator substituted false for the missing map
    // entry, so it distinguishes an evaluation error from an ordinary false value.
    assert!(matches!(
        decision("request.resource == false"),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
    assert!(matches!(
        decision("request.query == false"),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));

    // Anonymous callers have an explicitly present null auth member.
    assert!(matches!(decision("request.auth == null"), Decision::Allow));

    // The absent members are also absent from the request map's key set.
    assert!(matches!(
        decision("request.keys() == ['auth', 'method', 'path', 'time']"),
        Decision::Allow
    ));
    assert!(matches!(
        decision("request.keys().hasAny(['resource', 'query'])"),
        Decision::Deny(DenyReason::NoMatchingAllow)
    ));
}

#[test]
fn regex_step_budget_exhaustion_denies_replace() {
    let rules = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if resource.data.value.replace('z', 'x') == resource.data.value;
    }
  }
}
";
    let ruleset = parse_ruleset(rules).unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[("value", RulesValue::String("a".repeat(210_000)))]));

    let report = evaluate_request(&ruleset, &request);
    assert!(
        matches!(
            report.decision,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "FIREEMU-REGEX-STEPS-PER-MATCH",
                current,
                maximum,
            }) if current > maximum
        ),
        "{report:?}"
    );
}

#[test]
fn regex_step_budget_exhaustion_cannot_be_overridden_by_a_nested_allow() {
    let rules = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if resource.data.value.replace('z', 'x') == resource.data.value;
      match /{rest=**} {
        allow get: if true;
      }
    }
  }
}
";
    let ruleset = parse_ruleset(rules).unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[("value", RulesValue::String("a".repeat(210_000)))]));

    let report = evaluate_request(&ruleset, &request);
    assert!(
        matches!(
            report.decision,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "FIREEMU-REGEX-STEPS-PER-MATCH",
                current,
                maximum,
            }) if current > maximum
        ),
        "{report:?}"
    );
}

#[test]
fn dynamic_invalid_regex_diagnostics_escape_unicode_format_characters() {
    let ruleset = parse_ruleset(
        r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if 'x'.matches(resource.data.pattern);
    }
  }
}
",
    )
    .unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[(
        "pattern",
        RulesValue::String("\\p{\u{202e}}".to_owned()),
    )]));

    let report = evaluate_request(&ruleset, &request);
    let Decision::Deny(DenyReason::Unsupported(message)) = report.decision else {
        panic!("{report:?}");
    };
    assert!(!message.contains('\u{202e}'), "{message}");
    assert!(message.contains("\\u{202e}"), "{message}");
}

#[test]
fn regex_backtracking_step_budget_cannot_be_overridden_by_a_nested_allow() {
    let rules = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow get: if resource.data.value.matches('(a|aa)*b') == false;
      match /{rest=**} {
        allow get: if true;
      }
    }
  }
}
";
    let ruleset = parse_ruleset(rules).unwrap();
    let mut request = ctx(Method::Get, "/databases/(default)/documents/notes/n1", None);
    request.resource = Some(doc(&[("value", RulesValue::String("a".repeat(10_000)))]));

    let report = evaluate_request(&ruleset, &request);
    assert!(
        matches!(
            report.decision,
            Decision::Deny(DenyReason::BudgetExceeded {
                limit_id: "FIREEMU-REGEX-STEPS-PER-MATCH",
                current,
                maximum,
            }) if current > maximum
        ),
        "{report:?}"
    );
}
