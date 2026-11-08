//! Differences from the official Firestore emulator (firebase-tools 15.28.2) in query
//! authorization that a user reported, decided by the FS-RULES-DIFFS production recording of
//! 2026-11-08 (`conformance/fs-rules-v1-observation.json`, programs `fs-rules-v1/diffs/*`, two
//! identical recordings). Production answered as the official emulator in every row below, so
//! both profiles give the recorded answer. A `runQuery` 200 is an allow, a 403 a deny.

use super::*;

fn query_mut(request: &mut pb::RunQueryRequest) -> &mut pb::StructuredQuery {
    match &mut request.query_type {
        Some(pb::run_query_request::QueryType::StructuredQuery(query)) => query,
        _ => unreachable!("structured query"),
    }
}

fn field_filter(field: &str, op: sq::field_filter::Operator, value: pb::Value) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: field.to_owned(),
            }),
            op: op as i32,
            value: Some(value),
        })),
    }
}

fn and(filters: Vec<sq::Filter>) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::CompositeFilter(
            sq::CompositeFilter {
                op: sq::composite_filter::Operator::And as i32,
                filters,
            },
        )),
    }
}

fn reference(path: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::ReferenceValue(format!(
            "{DOCS}/{path}"
        ))),
    }
}

/// The two compatibility profiles as far as query authorization is concerned: `strict`
/// (verified tokens, refusal without a ruleset, no end-user read-write transactions) and
/// `emulator` (the official emulator's mock tokens).
async fn start_profiles() -> [(&'static str, Harness); 2] {
    let strict = start_with_enforcer(TokenAcceptance::Verified, IndexSet::default(), |e| {
        e.with_refusal_without_ruleset(true)
            .with_end_user_transactions(false)
    })
    .await;
    let emulator = start_with(TokenAcceptance::EmulatorMock).await;
    [("strict", strict), ("emulator", emulator)]
}

fn doc_name(path: &str) -> String {
    format!("{DOCS}/{path}")
}

/// Runs the query and returns the names of the documents, or the status code.
async fn run(
    h: &mut Harness,
    request: pb::RunQueryRequest,
    token: &str,
) -> Result<Vec<String>, tonic::Code> {
    let mut stream = h
        .client
        .run_query(with_bearer(request, token))
        .await
        .map_err(|status| status.code())?
        .into_inner();
    let mut names = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(response) => names.extend(response.document.map(|d| d.name)),
            Err(status) => return Err(status.code()),
        }
    }
    Ok(names)
}

const OWNER_RULES: &str = "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /tasks/{id} { allow list: if resource.data.owner == request.auth.uid; }
  }
}";

fn name_filter(id: &str) -> sq::Filter {
    field_filter(
        "__name__",
        sq::field_filter::Operator::Equal,
        reference(&format!("tasks/{id}")),
    )
}

fn owner_filter(uid: &str) -> sq::Filter {
    field_filter("owner", sq::field_filter::Operator::Equal, s(uid))
}

fn tasks_where(filter: Option<sq::Filter>) -> pb::RunQueryRequest {
    let mut request = list("tasks");
    query_mut(&mut request).r#where = filter;
    request
}

/// Seeds `tasks/mine` (owned by the caller) and `tasks/theirs` (owned by someone else), loads
/// [`OWNER_RULES`] and returns the caller's uid and token.
async fn seed_tasks(h: &mut Harness) -> (String, String) {
    let (alice, token) = h.user("alice@example.com");
    h.client
        .commit(with_bearer(
            commit(vec![
                set_write("tasks/mine", &[("owner", s(&alice))]),
                set_write("tasks/theirs", &[("owner", s("other-owner"))]),
            ]),
            "owner",
        ))
        .await
        .unwrap();
    h.rules.replace_source(OWNER_RULES).unwrap();
    (alice, token)
}

// ----------------------------------------------------------------------------------------
// Case 1: owner == uid AND documentId() == name
// ----------------------------------------------------------------------------------------

/// Rows `fs-rules-v1/diffs/queries#owner-alone`, `#owner-and-name-missing`,
/// `#owner-and-name-foreign`, `#owner-and-name-own`, `#name-missing-alone` and
/// `#name-foreign-alone` (2026-11-08): a query whose filters name a document is checked
/// against that document, whatever else it filters on.
#[tokio::test]
async fn a_query_naming_a_document_is_checked_against_that_document() {
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = seed_tasks(&mut h).await;
        let owner_and =
            |id: &str| tasks_where(Some(and(vec![owner_filter(&alice), name_filter(id)])));
        let cases = [
            (
                "owner-alone",
                tasks_where(Some(owner_filter(&alice))),
                Ok(vec![doc_name("tasks/mine")]),
            ),
            (
                "owner-and-name-missing",
                owner_and("missing"),
                Err(tonic::Code::PermissionDenied),
            ),
            (
                "owner-and-name-foreign",
                owner_and("theirs"),
                Err(tonic::Code::PermissionDenied),
            ),
            (
                "owner-and-name-own",
                owner_and("mine"),
                Ok(vec![doc_name("tasks/mine")]),
            ),
            (
                "name-missing-alone",
                tasks_where(Some(name_filter("missing"))),
                Err(tonic::Code::PermissionDenied),
            ),
            (
                "name-foreign-alone",
                tasks_where(Some(name_filter("theirs"))),
                Err(tonic::Code::PermissionDenied),
            ),
        ];
        for (row, request, expected) in cases {
            assert_eq!(
                run(&mut h, request, &token).await,
                expected,
                "{profile} {row}"
            );
        }
        h.handle.abort();
    }
}

/// Naming a document never widens what the filters alone prove: a query naming the caller's
/// own document but filtering on another owner stays refused, as it was before the named
/// document was checked (production did not record this shape; refusing it keeps the
/// decision at least as strict as either check alone). An `OR` whose every branch names a
/// document checks each named document.
#[tokio::test]
async fn naming_a_document_adds_a_check_and_never_replaces_the_filter_proof() {
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = seed_tasks(&mut h).await;
        let other_owner_and_mine = tasks_where(Some(and(vec![
            owner_filter("other-owner"),
            name_filter("mine"),
        ])));
        assert_eq!(
            run(&mut h, other_owner_and_mine, &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile}"
        );
        let either = |second: &str| {
            tasks_where(Some(sq::Filter {
                filter_type: Some(sq::filter::FilterType::CompositeFilter(
                    sq::CompositeFilter {
                        op: sq::composite_filter::Operator::Or as i32,
                        filters: vec![
                            and(vec![owner_filter(&alice), name_filter("mine")]),
                            and(vec![owner_filter(&alice), name_filter(second)]),
                        ],
                    },
                )),
            }))
        };
        assert_eq!(
            run(&mut h, either("mine"), &token).await,
            Ok(vec![doc_name("tasks/mine")]),
            "{profile}"
        );
        assert_eq!(
            run(&mut h, either("theirs"), &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile}"
        );
        assert_eq!(
            run(&mut h, either("missing"), &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile}"
        );
        // One branch names the document alone, the other also filters on another owner: the
        // filtered branch still needs its constraint proof.
        let mixed = tasks_where(Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::Or as i32,
                    filters: vec![
                        name_filter("mine"),
                        and(vec![owner_filter("other-owner"), name_filter("mine")]),
                    ],
                },
            )),
        }));
        assert_eq!(
            run(&mut h, mixed, &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile}"
        );
        // A branch that names no document keeps the constraint proof for the whole query.
        let unnamed_branch = tasks_where(Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::Or as i32,
                    filters: vec![name_filter("mine"), owner_filter("other-owner")],
                },
            )),
        }));
        assert_eq!(
            run(&mut h, unnamed_branch, &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile}"
        );
        // A reference-valued filter on another field names no document: the constraint proof
        // alone decides, so a reference to a missing document does not refuse.
        let link_missing = tasks_where(Some(and(vec![
            owner_filter(&alice),
            field_filter(
                "link",
                sq::field_filter::Operator::Equal,
                reference("tasks/missing"),
            ),
        ])));
        assert_eq!(
            run(&mut h, link_missing, &token).await,
            Ok(vec![]),
            "{profile}"
        );
        // Two names in one branch: each named document is checked.
        let two_names = tasks_where(Some(and(vec![
            owner_filter(&alice),
            name_filter("theirs"),
            name_filter("mine"),
        ])));
        assert_eq!(
            run(&mut h, two_names, &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile}"
        );
        h.handle.abort();
    }
}

/// Every combination of which document is named (none, the caller's, someone else's, a
/// missing one) and which owner is filtered on (none, the caller, someone else): the query is
/// allowed exactly when the owner filter proves the rule (if there is one) and the named
/// document exists and passes the rule (if one is named). With neither filter the rule
/// cannot be proven.
#[tokio::test]
async fn named_documents_and_owner_filters_combine_as_a_conjunction() {
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = seed_tasks(&mut h).await;
        for named in [None, Some("mine"), Some("theirs"), Some("missing")] {
            for owner in [None, Some(alice.as_str()), Some("other-owner")] {
                let mut filters = Vec::new();
                filters.extend(owner.map(owner_filter));
                filters.extend(named.map(name_filter));
                let filter = match filters.len() {
                    0 => None,
                    1 => filters.pop(),
                    _ => Some(and(filters)),
                };
                let named_passes = named.map(|id| id == "mine");
                let owner_proves = owner.map(|uid| uid == alice);
                let allowed = match (named_passes, owner_proves) {
                    (None, None) => false,
                    (Some(n), None) => n,
                    (None, Some(o)) => o,
                    (Some(n), Some(o)) => n && o,
                };
                let answer = run(&mut h, tasks_where(filter), &token).await;
                assert_eq!(
                    answer.is_ok(),
                    allowed,
                    "{profile} named={named:?} owner={owner:?}: {answer:?}"
                );
                if !allowed {
                    assert_eq!(answer, Err(tonic::Code::PermissionDenied));
                }
            }
        }
        h.handle.abort();
    }
}

// ----------------------------------------------------------------------------------------
// Case 2: `resource != null &&` guard with where("members.<uid>.role", "in", [...])
// ----------------------------------------------------------------------------------------

fn members_role_in(collection: &str, uid: &str, roles: &[&str]) -> pb::RunQueryRequest {
    let mut request = list(collection);
    let roles = pb::Value {
        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
            values: roles.iter().map(|role| s(role)).collect(),
        })),
    };
    query_mut(&mut request).r#where = Some(field_filter(
        &format!("members.`{uid}`.role"),
        sq::field_filter::Operator::In,
        roles,
    ));
    request
}

const MEMBERS_RULES: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /guarded/{id} { allow list: if resource != null && resource.data.members[request.auth.uid].role in ["ADMIN", "MEMBER"]; }
    match /unguarded/{id} { allow list: if resource.data.members[request.auth.uid].role in ["ADMIN", "MEMBER"]; }
    match /bare/{id} { allow list: if resource != null; }
  }
}"#;

/// Rows `fs-rules-v1/diffs/queries#members-guarded-in`, `#members-guarded-in-viewer`,
/// `#members-unguarded-in` and `#members-bare-nofilter` (2026-11-08): the query's `resource`
/// is a document, so `resource != null` holds whatever its fields are.
#[tokio::test]
async fn the_query_resource_is_never_null() {
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = h.user("alice@example.com");
        h.rules.replace_source(MEMBERS_RULES).unwrap();
        let cases = [
            (
                "guarded-in",
                members_role_in("guarded", &alice, &["ADMIN", "MEMBER"]),
                true,
            ),
            (
                "guarded-in-viewer",
                members_role_in("guarded", &alice, &["VIEWER"]),
                false,
            ),
            (
                "unguarded-in",
                members_role_in("unguarded", &alice, &["ADMIN", "MEMBER"]),
                true,
            ),
            ("bare-nofilter", list("bare"), true),
        ];
        for (row, request, allowed) in cases {
            let answer = run(&mut h, request, &token).await;
            let expected = if allowed {
                Ok(vec![])
            } else {
                Err(tonic::Code::PermissionDenied)
            };
            assert_eq!(answer, expected, "{profile} {row}");
        }
        h.handle.abort();
    }
}

// ----------------------------------------------------------------------------------------
// Case 5: `!("blocked" in resource.data)` with no filter
// ----------------------------------------------------------------------------------------

const KEY_RULES: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /blocked/{id} { allow list: if !("blocked" in resource.data); }
    match /has-owner/{id} { allow list: if "owner" in resource.data; }
  }
}"#;

/// Rows `fs-rules-v1/diffs/queries#blocked-nofilter`, `#has-owner-nofilter` and
/// `#has-owner-filtered` (2026-11-08): in a query proof a key the query does not constrain is
/// not in `resource.data`.
#[tokio::test]
async fn a_key_the_query_does_not_constrain_is_not_in_the_query_resource_data() {
    for (profile, mut h) in start_profiles().await {
        let (_alice, token) = h.user("alice@example.com");
        h.rules.replace_source(KEY_RULES).unwrap();
        let mut filtered = list("has-owner");
        query_mut(&mut filtered).r#where = Some(owner_filter("o1"));
        let cases = [
            ("blocked-nofilter", list("blocked"), true),
            ("has-owner-nofilter", list("has-owner"), false),
            ("has-owner-filtered", filtered, true),
        ];
        for (row, request, allowed) in cases {
            let answer = run(&mut h, request, &token).await;
            let expected = if allowed {
                Ok(vec![])
            } else {
                Err(tonic::Code::PermissionDenied)
            };
            assert_eq!(answer, expected, "{profile} {row}");
        }
        h.handle.abort();
    }
}
