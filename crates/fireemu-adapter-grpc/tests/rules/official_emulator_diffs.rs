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
            .with_official_query_answers(false)
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

fn or(filters: Vec<sq::Filter>) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::CompositeFilter(
            sq::CompositeFilter {
                op: sq::composite_filter::Operator::Or as i32,
                filters,
            },
        )),
    }
}

fn n_is_1() -> sq::Filter {
    field_filter("n", sq::field_filter::Operator::Equal, integer(1))
}

/// Rows `fs-rules-v1/shapes/queries#name-own-alone`, `#two-names-own`, `#two-names-mixed`,
/// `#or-foreign-unnamed`, `#own-plus-unproven`, `#name-own-range`, `#name-own-limit` and
/// `#name-own-cursor` (FS-RULES-SHAPES, 2026-11-08; the official emulator answered the same): a
/// branch that names one document is decided by that document, whatever else it filters on and
/// also with a limit or a cursor; two names in one branch are refused even when both
/// documents pass; a range on the name names no document.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn one_named_document_decides_its_branch() {
    use sq::field_filter::Operator as Op;
    let cursor = |request: &mut pb::RunQueryRequest| {
        let q = query_mut(request);
        q.order_by = vec![sq::Order {
            field: Some(sq::FieldReference {
                field_path: "__name__".to_owned(),
            }),
            direction: sq::Direction::Ascending as i32,
        }];
        q.start_at = Some(pb::Cursor {
            values: vec![reference("tasks/mine")],
            before: true,
        });
    };
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = seed_tasks(&mut h).await;
        h.client
            .commit(with_bearer(
                commit(vec![
                    set_write("tasks/mine", &[("owner", s(&alice)), ("n", integer(1))]),
                    set_write("tasks/mine2", &[("owner", s(&alice)), ("n", integer(1))]),
                ]),
                "owner",
            ))
            .await
            .unwrap();
        let mine = || Ok(vec![doc_name("tasks/mine")]);
        let denied = || Err(tonic::Code::PermissionDenied);
        let mut limited = tasks_where(Some(name_filter("mine")));
        query_mut(&mut limited).limit = Some(1);
        let mut cursored = tasks_where(Some(name_filter("mine")));
        cursor(&mut cursored);
        let range = tasks_where(Some(and(vec![
            field_filter("__name__", Op::GreaterThanOrEqual, reference("tasks/mine")),
            field_filter("__name__", Op::LessThanOrEqual, reference("tasks/mine")),
        ])));
        let cases = [
            (
                "name-own-alone",
                tasks_where(Some(name_filter("mine"))),
                mine(),
            ),
            (
                "two-names-own",
                tasks_where(Some(and(vec![name_filter("mine"), name_filter("mine2")]))),
                denied(),
            ),
            (
                "two-names-mixed",
                tasks_where(Some(and(vec![name_filter("mine"), name_filter("theirs")]))),
                denied(),
            ),
            (
                "or-foreign-unnamed",
                tasks_where(Some(or(vec![name_filter("theirs"), owner_filter(&alice)]))),
                denied(),
            ),
            (
                "own-plus-unproven",
                tasks_where(Some(and(vec![name_filter("mine"), n_is_1()]))),
                mine(),
            ),
            ("name-own-range", range, denied()),
            ("name-own-limit", limited, mine()),
            ("name-own-cursor", cursored, mine()),
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

/// Row `fs-rules-v1/shapes/queries#or-named-unnamed` (`documentId() == <own> OR owner == uid`):
/// production answered 400 for a missing composite index (`FAILED_PRECONDITION`), so its Rules
/// answer is not recorded; the official emulator allows it. The `emulator` profile authorizes
/// each branch on its own (the named branch by its document, the other by its constraint
/// proof) and allows it as the official emulator does; `strict` does not allow what
/// production has not shown and proves every branch from its constraints, so it refuses.
/// A branch neither check proves refuses in both.
#[tokio::test]
async fn an_or_mixing_a_named_and_an_unnamed_branch_follows_each_profile() {
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = seed_tasks(&mut h).await;
        let either = |second: sq::Filter| tasks_where(Some(or(vec![name_filter("mine"), second])));
        let expected = if profile == "strict" {
            Err(tonic::Code::PermissionDenied)
        } else {
            Ok(vec![doc_name("tasks/mine")])
        };
        assert_eq!(
            run(&mut h, either(owner_filter(&alice)), &token).await,
            expected,
            "{profile} or-named-unnamed"
        );
        assert_eq!(
            run(&mut h, either(owner_filter("other-owner")), &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile} a branch the filters do not prove"
        );
        // Every branch names one document: each is decided by it, in both profiles.
        assert_eq!(
            run(&mut h, either(name_filter("mine")), &token).await,
            Ok(vec![doc_name("tasks/mine")]),
            "{profile} two named branches"
        );
        assert_eq!(
            run(&mut h, either(name_filter("missing")), &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile} a branch naming a missing document"
        );
        h.handle.abort();
    }
}

/// Every combination of which document is named (none, the caller's, someone else's, a
/// missing one) and which owner is filtered on (none, the caller, someone else): a named
/// document decides alone (`own-plus-unproven`); without one the owner filter must prove the
/// rule, also with an offset. A reference-valued filter on another field names nothing.
#[tokio::test]
async fn a_named_document_decides_and_otherwise_the_filters_must_prove() {
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
                let allowed = match named {
                    Some(id) => id == "mine",
                    None => owner == Some(alice.as_str()),
                };
                let answer = run(&mut h, tasks_where(filter.clone()), &token).await;
                assert_eq!(
                    answer.is_ok(),
                    allowed,
                    "{profile} named={named:?} owner={owner:?}: {answer:?}"
                );
                if !allowed {
                    assert_eq!(answer, Err(tonic::Code::PermissionDenied));
                }
                // An offset changes nothing (FS-RULES-SHAPES-TWO `name-offset`,
                // `owner-offset` allowed, `foreign-offset` refused).
                let mut offset = tasks_where(filter);
                query_mut(&mut offset).offset = 1;
                assert_eq!(
                    run(&mut h, offset, &token).await.is_ok(),
                    allowed,
                    "{profile} offset named={named:?} owner={owner:?}"
                );
            }
        }
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
            "{profile} link"
        );
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

fn unary_filter(field: &str, op: sq::unary_filter::Operator) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::UnaryFilter(sq::UnaryFilter {
            op: op as i32,
            operand_type: Some(sq::unary_filter::OperandType::Field(sq::FieldReference {
                field_path: field.to_owned(),
            })),
        })),
    }
}

fn array(values: Vec<pb::Value>) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue { values })),
    }
}

/// Every filter, ordering or cursor that only matches documents holding `x` makes `x` a key of
/// the query's `resource.data`, so `!("x" in resource.data)` is never proven for it (review
/// 2026-11-08: `where("x", "!=", null)` was authorized). Only the unfiltered query and a query
/// on another field stay allowed.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_constraint_that_implies_the_key_keeps_it_in_the_query_resource_data() {
    use sq::field_filter::Operator as Op;
    use sq::unary_filter::Operator as Unary;
    const ABSENT_RULES: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /absent/{id} { allow list: if !("x" in resource.data); }
  }
}"#;
    let query = |filter: Option<sq::Filter>, order: Option<&str>, cursor: bool| {
        let mut request = list("absent");
        let q = query_mut(&mut request);
        q.r#where = filter;
        if let Some(field) = order {
            q.order_by = vec![sq::Order {
                field: Some(sq::FieldReference {
                    field_path: field.to_owned(),
                }),
                direction: sq::Direction::Ascending as i32,
            }];
            if cursor {
                q.start_at = Some(pb::Cursor {
                    values: vec![integer(0)],
                    before: true,
                });
            }
        }
        request
    };
    let x = |op: Op, value: pb::Value| Some(field_filter("x", op, value));
    for (profile, mut h) in start_profiles().await {
        let (_alice, token) = h.user("alice@example.com");
        h.rules.replace_source(ABSENT_RULES).unwrap();
        let allowed = [
            ("unfiltered", query(None, None, false)),
            ("other field", query(Some(owner_filter("o1")), None, false)),
        ];
        for (case, request) in allowed {
            assert_eq!(
                run(&mut h, request, &token).await,
                Ok(vec![]),
                "{profile} {case}"
            );
        }
        let refused = [
            (
                "is not null",
                query(Some(unary_filter("x", Unary::IsNotNull)), None, false),
            ),
            (
                "is nan",
                query(Some(unary_filter("x", Unary::IsNan)), None, false),
            ),
            (
                "is not nan",
                query(Some(unary_filter("x", Unary::IsNotNan)), None, false),
            ),
            (
                "is null",
                query(Some(unary_filter("x", Unary::IsNull)), None, false),
            ),
            ("equal", query(x(Op::Equal, integer(1)), None, false)),
            ("not equal", query(x(Op::NotEqual, integer(1)), None, false)),
            (
                "not in",
                query(x(Op::NotIn, array(vec![integer(1)])), None, false),
            ),
            ("in", query(x(Op::In, array(vec![integer(1)])), None, false)),
            (
                "greater than",
                query(x(Op::GreaterThan, integer(0)), None, false),
            ),
            (
                "array contains",
                query(x(Op::ArrayContains, integer(1)), None, false),
            ),
            (
                "array contains any",
                query(
                    x(Op::ArrayContainsAny, array(vec![integer(1)])),
                    None,
                    false,
                ),
            ),
            (
                "nested field",
                query(
                    Some(field_filter("x.y", Op::Equal, integer(1))),
                    None,
                    false,
                ),
            ),
            ("order by", query(None, Some("x"), false)),
            ("order by with a cursor", query(None, Some("x"), true)),
        ];
        for (case, request) in refused {
            assert_eq!(
                run(&mut h, request, &token).await,
                Err(tonic::Code::PermissionDenied),
                "{profile} {case}"
            );
        }
        h.handle.abort();
    }
}

const SHAPES_RULES: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /nested-neg/{id} { allow list: if !("blocked" in resource.data.meta); }
    match /nested-pos/{id} { allow list: if "a" in resource.data.meta; }
    match /keys-neg/{id} { allow list: if !resource.data.keys().hasAny(["blocked"]); }
    match /keys-pos/{id} { allow list: if resource.data.keys().hasAll(["a"]); }
    match /size/{id} { allow list: if resource.data.size() > 0; }
    match /get-neg/{id} { allow list: if resource.data.get("blocked", false) == false; }
    match /get-pos/{id} { allow list: if resource.data.get("a", 0) == 1; }
    match /{path=**}/cg/{id} { allow list: if !("blocked" in resource.data); }
    match /{path=**}/cg-has/{id} { allow list: if "blocked" in resource.data; }
    match /{path=**}/blk/{id} { allow list: if !("blocked" in resource.data); }
    match /sec-list/{id} { allow list: if [resource.data.secret] != null; }
    match /sec-map/{id} { allow list: if {"k": resource.data.secret} != null; }
    match /sec-bare/{id} { allow list: if resource.data.secret != null; }
    match /sec-owner/{id} { allow list: if [resource.data.owner] != null; }
  }
}"#;

/// The query rows of FS-RULES-SHAPES (2026-11-08, two identical recordings; the official
/// emulator answered the same on each), seeded as production was: in a query proof
/// `resource.data` holds the keys the query constrains and only those, for `in` (also of a
/// map the query constrains in part), `keys()`, `size()` and `get()` with a default, whatever
/// the stored documents hold; a filter that implies a key makes it present; a list or map
/// built from a field the query does not constrain is not provably non-null.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_query_resource_data_holds_the_constrained_keys_only() {
    use sq::field_filter::Operator as Op;
    let from = |collection: &str, group: bool, filter: Option<sq::Filter>| {
        let mut request = list(collection);
        let q = query_mut(&mut request);
        q.from[0].all_descendants = group;
        q.r#where = filter;
        request
    };
    let a_is_1 = || Some(field_filter("a", Op::Equal, integer(1)));
    let meta_a_is_1 = || Some(field_filter("meta.a", Op::Equal, integer(1)));
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = h.user("alice@example.com");
        let mine = |collection: &str| {
            set_write(
                &format!("{collection}/s1"),
                &[("owner", s(&alice)), ("n", integer(1))],
            )
        };
        let a1 = |path: &str| set_write(path, &[("a", integer(1))]);
        h.client
            .commit(with_bearer(
                commit(vec![
                    set_write("nested-neg/d1", &[("meta", map(&[("a", integer(1))]))]),
                    set_write("nested-pos/d1", &[("meta", map(&[("a", integer(1))]))]),
                    a1("keys-neg/d1"),
                    a1("keys-pos/d1"),
                    a1("size/d1"),
                    a1("get-neg/d1"),
                    a1("get-pos/d1"),
                    set_write("cg/c1", &[("n", integer(1))]),
                    set_write("x/y/cg/c2", &[("n", integer(1))]),
                    set_write("cg-has/c1", &[("n", integer(1))]),
                    set_write("blk/b1", &[("blocked", bool_value(true))]),
                    set_write("x/y/blk/b2", &[("blocked", bool_value(true))]),
                    mine("sec-list"),
                    mine("sec-map"),
                    mine("sec-bare"),
                    mine("sec-owner"),
                ]),
                "owner",
            ))
            .await
            .unwrap();
        h.rules.replace_source(SHAPES_RULES).unwrap();
        let me = || Some(owner_filter(&alice));
        let rows = [
            (
                "nested-neg-nofilter",
                from("nested-neg", false, None),
                false,
            ),
            (
                "nested-neg-filtered",
                from("nested-neg", false, meta_a_is_1()),
                true,
            ),
            (
                "nested-pos-nofilter",
                from("nested-pos", false, None),
                false,
            ),
            (
                "nested-pos-filtered",
                from("nested-pos", false, meta_a_is_1()),
                true,
            ),
            ("keys-neg-nofilter", from("keys-neg", false, None), true),
            ("keys-neg-filtered", from("keys-neg", false, a_is_1()), true),
            ("keys-pos-nofilter", from("keys-pos", false, None), false),
            ("keys-pos-filtered", from("keys-pos", false, a_is_1()), true),
            ("size-nofilter", from("size", false, None), false),
            ("size-filtered", from("size", false, a_is_1()), true),
            ("get-neg-nofilter", from("get-neg", false, None), true),
            ("get-neg-filtered", from("get-neg", false, a_is_1()), true),
            ("get-pos-nofilter", from("get-pos", false, None), false),
            ("get-pos-filtered", from("get-pos", false, a_is_1()), true),
            ("cg-blocked-group", from("cg", true, None), true),
            ("cg-has-group", from("cg-has", true, None), false),
            ("cg-blocked-single", from("cg", false, None), true),
            ("blk-stored-nofilter", from("blk", false, None), true),
            (
                "blk-not-null",
                from(
                    "blk",
                    false,
                    Some(unary_filter(
                        "blocked",
                        sq::unary_filter::Operator::IsNotNull,
                    )),
                ),
                false,
            ),
            ("blk-stored-group", from("blk", true, None), true),
            (
                "blk-eq-true",
                from(
                    "blk",
                    false,
                    Some(field_filter("blocked", Op::Equal, bool_value(true))),
                ),
                false,
            ),
            ("sec-list-owner", from("sec-list", false, me()), false),
            ("sec-map-owner", from("sec-map", false, me()), false),
            ("sec-bare-owner", from("sec-bare", false, me()), false),
            ("sec-owner-owner", from("sec-owner", false, me()), true),
        ];
        for (row, request, allowed) in rows {
            let answer = run(&mut h, request, &token).await;
            assert_eq!(answer.is_ok(), allowed, "{profile} {row}: {answer:?}");
            if !allowed {
                assert_eq!(
                    answer,
                    Err(tonic::Code::PermissionDenied),
                    "{profile} {row}"
                );
            }
        }
        h.handle.abort();
    }
}

fn bool_value(value: bool) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::BooleanValue(value)),
    }
}

/// The review's cases (2026-11-08 r2), each over a stored document the rule would refuse if it
/// were evaluated: production authorizes a query from its constraints, not the stored
/// documents, so `keys().hasOnly`, `size() == 1`, `get` with a default and `in` on a map the
/// query constrains in part are allowed (FS-RULES-SHAPES-TWO only-extra, size-extra,
/// get-stored, meta-stored); a look-alike of the query resource built from a missing field is
/// not proven.
#[tokio::test]
async fn key_set_reads_follow_the_constraints_and_look_alike_resources_are_not_proven() {
    use sq::field_filter::Operator as Op;
    const REVIEW_RULES: &str = r"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /has-only/{id} { allow list: if resource.data.keys().hasOnly(['a']); }
    match /size-one/{id} { allow list: if resource.data.size() == 1; }
    match /get-default/{id} { allow list: if resource.data.get('blocked', false) == false; }
    match /nested/{id} { allow list: if !('blocked' in resource.data.meta); }
    match /look-alike/{id} { allow list: if {'data': resource.data, 'id': resource.data.secret, '__name__': resource.data.secret} != null; }
  }
}";
    for (profile, mut h) in start_profiles().await {
        let (_alice, token) = h.user("alice@example.com");
        let a_blocked =
            |path: &str| set_write(path, &[("a", integer(1)), ("blocked", bool_value(true))]);
        h.client
            .commit(with_bearer(
                commit(vec![
                    a_blocked("has-only/d"),
                    a_blocked("size-one/d"),
                    a_blocked("get-default/d"),
                    set_write(
                        "nested/d",
                        &[(
                            "meta",
                            map(&[("a", integer(1)), ("blocked", bool_value(true))]),
                        )],
                    ),
                    set_write("look-alike/d", &[("a", integer(1))]),
                ]),
                "owner",
            ))
            .await
            .unwrap();
        h.rules.replace_source(REVIEW_RULES).unwrap();
        let filtered = |collection: &str, field: &str| {
            let mut request = list(collection);
            query_mut(&mut request).r#where = Some(field_filter(field, Op::Equal, integer(1)));
            request
        };
        let rows = [
            ("has-only", filtered("has-only", "a"), true),
            ("size-one", filtered("size-one", "a"), true),
            ("look-alike", filtered("look-alike", "a"), false),
            ("get-default", filtered("get-default", "a"), true),
            ("nested", filtered("nested", "meta.a"), true),
        ];
        for (row, request, allowed) in rows {
            let answer = run(&mut h, request, &token).await;
            assert_eq!(answer.is_ok(), allowed, "{profile} {row}: {answer:?}");
            if !allowed {
                assert_eq!(
                    answer,
                    Err(tonic::Code::PermissionDenied),
                    "{profile} {row}"
                );
            }
        }
        h.handle.abort();
    }
}

/// A signed-in user whose ID token carries `admin: true`.
fn admin_token(h: &Harness) -> String {
    let mut store = h.auth.lock().unwrap();
    let uid = store
        .create_user(NewUser::email("admin@example.com"), START)
        .unwrap();
    let claims =
        fireemu_core_auth::claims::CustomClaims::parse_attributes(r#"{"admin":true}"#).unwrap();
    store.set_custom_claims(&uid, claims).unwrap();
    encode_unsigned(&store.id_token_claims(&uid, None, START).unwrap())
}

/// The review's cases (2026-11-08 r6): an admin-override helper called with a value that
/// exists but is undetermined (`resource.id`, a field the query orders by) is decided by the
/// helper, in both profiles; the same helper with an unconstrained field is not.
#[tokio::test]
async fn a_helper_called_with_a_present_undetermined_value_decides() {
    const HELPER_RULES: &str = r"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function canRead(id) { return request.auth.token.admin == true || id == request.auth.uid; }
    function isPublished(createdAt) { return request.auth.token.admin == true || createdAt <= request.time; }
    match /byId/{id} { allow list: if canRead(resource.id); }
    match /posts/{id} { allow list: if isPublished(resource.data.createdAt); }
    match /secret/{id} { allow list: if isPublished(resource.data.secret); }
    match /absorbed/{id} { allow list: if canRead((resource.data.secret == 1 || true) ? resource.id : resource.id); }
    match /unabsorbed/{id} { allow list: if canRead((resource.data.secret == 1 && true) ? resource.id : resource.id); }
  }
}";
    for (profile, mut h) in start_profiles().await {
        let token = admin_token(&h);
        h.client
            .commit(with_bearer(
                commit(vec![
                    set_write("byId/d", &[("a", integer(1))]),
                    set_write("posts/p", &[("createdAt", integer(1))]),
                    set_write("secret/s", &[("a", integer(1))]),
                    set_write("absorbed/d", &[("a", integer(1))]),
                    set_write("unabsorbed/d", &[("a", integer(1))]),
                ]),
                "owner",
            ))
            .await
            .unwrap();
        h.rules.replace_source(HELPER_RULES).unwrap();
        let mut by_id = list("byId");
        query_mut(&mut by_id).r#where = Some(field_filter(
            "a",
            sq::field_filter::Operator::Equal,
            integer(1),
        ));
        let ordered = |collection: &str, field: &str| {
            let mut request = list(collection);
            query_mut(&mut request).order_by = vec![sq::Order {
                field: Some(sq::FieldReference {
                    field_path: field.to_owned(),
                }),
                direction: sq::Direction::Ascending as i32,
            }];
            request
        };
        let rows = [
            ("byId", by_id, true),
            ("posts", ordered("posts", "createdAt"), true),
            ("secret", ordered("secret", "a"), false),
            ("absorbed", ordered("absorbed", "a"), true),
            ("unabsorbed", ordered("unabsorbed", "a"), false),
        ];
        for (row, request, allowed) in rows {
            let answer = run(&mut h, request, &token).await;
            assert_eq!(answer.is_ok(), allowed, "{profile} {row}: {answer:?}");
        }
        h.handle.abort();
    }
}

/// The reviews' cases (2026-11-08 r3 and r4): a map or list the rule builds from a field the
/// query does not constrain may fail to build on a stored document lacking it, so no operation
/// on it (a shape read, a type test, a member of it) is proven, in either profile. Shape reads of `request` and `resource` stay proven.
#[tokio::test]
async fn shape_operations_on_a_built_container_do_not_hide_a_missing_field() {
    const SHAPE_RULES: &str = r"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function ignore(x) { return true; }
    function helper(x) { return {'ok': true}; }
    match /map-size/{id} { allow list: if {'k': resource.data.secret}.size() == 1; }
    match /map-keys/{id} { allow list: if {'k': resource.data.secret}.keys().hasOnly(['k']); }
    match /list-size/{id} { allow list: if [resource.data.secret].size() == 1; }
    match /map-is/{id} { allow list: if {'k': resource.data.secret} is map; }
    match /list-is/{id} { allow list: if [resource.data.secret] is list; }
    match /map-member/{id} { allow list: if {'bad': resource.data.secret, 'ok': true}.ok; }
    match /map-duplicate/{id} { allow list: if {'k': resource.data.secret, 'k': true}.k; }
    match /fn-ignore/{id} { allow list: if ignore(resource.data.secret); }
    match /fn-helper/{id} { allow list: if helper(resource.data.secret).ok; }
    match /request-keys/{id} { allow list: if request.keys().hasAll(['auth', 'path']); }
    match /resource-keys/{id} { allow list: if resource.keys().hasAll(['data', 'id']); }
  }
}";
    for (profile, mut h) in start_profiles().await {
        let (_alice, token) = h.user("alice@example.com");
        let a1 = |path: &str| set_write(path, &[("a", integer(1))]);
        h.client
            .commit(with_bearer(
                commit(vec![
                    a1("map-size/d"),
                    a1("map-keys/d"),
                    a1("list-size/d"),
                    a1("map-is/d"),
                    a1("list-is/d"),
                    a1("map-member/d"),
                    a1("map-duplicate/d"),
                    a1("fn-ignore/d"),
                    a1("fn-helper/d"),
                    a1("request-keys/d"),
                    a1("resource-keys/d"),
                ]),
                "owner",
            ))
            .await
            .unwrap();
        h.rules.replace_source(SHAPE_RULES).unwrap();
        let a_is_1 = |collection: &str| {
            let mut request = list(collection);
            query_mut(&mut request).r#where = Some(field_filter(
                "a",
                sq::field_filter::Operator::Equal,
                integer(1),
            ));
            request
        };
        let rows = [
            ("map-size", false),
            ("map-keys", false),
            ("list-size", false),
            ("map-is", false),
            ("list-is", false),
            ("map-member", false),
            ("map-duplicate", false),
            ("fn-ignore", false),
            ("fn-helper", false),
            ("request-keys", true),
            ("resource-keys", true),
        ];
        for (collection, allowed) in rows {
            let answer = run(&mut h, a_is_1(collection), &token).await;
            assert_eq!(
                answer.is_ok(),
                allowed,
                "{profile} {collection}: {answer:?}"
            );
            if !allowed {
                assert_eq!(
                    answer,
                    Err(tonic::Code::PermissionDenied),
                    "{profile} {collection}"
                );
            }
        }
        h.handle.abort();
    }
}

/// The rows of FS-RULES-SHAPES-TWO (2026-11-08 11:38-11:47Z, two identical recordings; the
/// official emulator answered the same), seeded as production was. Production authorizes a list
/// from the query's constraints, not from the stored documents: the query's `resource.data`
/// holds exactly the constrained keys, so `get` with a default, `keys()` (an exact list),
/// `size()` (an exact count) and `in` on a partially constrained map answer from them even when
/// the stored documents hold another key; `resource` passed to a function is still the
/// resource; a named document decides its branch also with an offset.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_second_shapes_rows_follow_production() {
    use sq::field_filter::Operator as Op;
    const SHAPES_TWO_RULES: &str = r"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function f(r) { return r != null; }
    function g(r) { return r == null; }
    match /ctl-true/{id} { allow list: if true; }
    match /ctl-false/{id} { allow list: if false; }
    match /get/{id} { allow list: if resource.data.get('blocked', false) == false; }
    match /get-absent/{id} { allow list: if resource.data.get('blocked', false) == false; }
    match /keys/{id} { allow list: if !resource.data.keys().hasAny(['blocked']); }
    match /keys-absent/{id} { allow list: if !resource.data.keys().hasAny(['blocked']); }
    match /meta/{id} { allow list: if !('blocked' in resource.data.meta); }
    match /meta-absent/{id} { allow list: if !('blocked' in resource.data.meta); }
    match /only-plain/{id} { allow list: if resource.data.keys().hasOnly(['a']); }
    match /only-extra/{id} { allow list: if resource.data.keys().hasOnly(['a']); }
    match /only-b/{id} { allow list: if resource.data.keys().hasOnly(['b']); }
    match /size-plain/{id} { allow list: if resource.data.size() == 1; }
    match /size-extra/{id} { allow list: if resource.data.size() == 1; }
    match /size-zero/{id} { allow list: if resource.data.size() == 0; }
    match /own/{id} { allow list: if resource.data.owner == request.auth.uid; }
    match /fn-resource/{id} { allow list: if f(resource); }
    match /fn-null/{id} { allow list: if g(resource); }
    match /fn-arg/{id} { allow list: if f(request.auth); }
  }
}";
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = h.user("alice@example.com");
        let a1 = |path: &str| set_write(path, &[("a", integer(1))]);
        let a1_and =
            |path: &str, key: &str| set_write(path, &[("a", integer(1)), (key, bool_value(true))]);
        h.client
            .commit(with_bearer(
                commit(vec![
                    a1("ctl-true/d1"),
                    a1("ctl-false/d1"),
                    a1_and("get/d1", "blocked"),
                    a1("get-absent/d1"),
                    a1_and("keys/d1", "blocked"),
                    a1("keys-absent/d1"),
                    set_write(
                        "meta/d1",
                        &[(
                            "meta",
                            map(&[("a", integer(1)), ("blocked", bool_value(true))]),
                        )],
                    ),
                    set_write("meta-absent/d1", &[("meta", map(&[("a", integer(1))]))]),
                    a1("only-plain/d1"),
                    a1_and("only-extra/d1", "extra"),
                    a1("only-b/d1"),
                    a1("size-plain/d1"),
                    a1_and("size-extra/d1", "extra"),
                    a1("size-zero/d1"),
                    set_write("own/mine", &[("owner", s(&alice)), ("n", integer(1))]),
                    set_write("own/mine2", &[("owner", s(&alice)), ("n", integer(1))]),
                    set_write(
                        "own/foreign",
                        &[("owner", s("other-owner")), ("n", integer(1))],
                    ),
                    a1("fn-resource/d1"),
                    a1("fn-null/d1"),
                    a1("fn-arg/d1"),
                ]),
                "owner",
            ))
            .await
            .unwrap();
        h.rules.replace_source(SHAPES_TWO_RULES).unwrap();
        let q = |collection: &str, filter: sq::Filter, offset: i32| {
            let mut request = list(collection);
            let query = query_mut(&mut request);
            query.r#where = Some(filter);
            query.offset = offset;
            request
        };
        let a_is_1 = || field_filter("a", Op::Equal, integer(1));
        let meta_a_is_1 = || field_filter("meta.a", Op::Equal, integer(1));
        let blocked_is = |value: bool| field_filter("blocked", Op::Equal, bool_value(value));
        let own_name =
            |id: &str| field_filter("__name__", Op::Equal, reference(&format!("own/{id}")));
        let rows = [
            ("ctl-allow", q("ctl-true", a_is_1(), 0), true),
            ("ctl-deny", q("ctl-false", a_is_1(), 0), false),
            ("get-stored", q("get", a_is_1(), 0), true),
            ("get-absent", q("get-absent", a_is_1(), 0), true),
            ("get-allow", q("get", blocked_is(false), 0), true),
            ("get-deny", q("get", blocked_is(true), 0), false),
            ("keys-stored", q("keys", a_is_1(), 0), true),
            ("keys-absent", q("keys-absent", a_is_1(), 0), true),
            ("keys-deny", q("keys", blocked_is(true), 0), false),
            ("meta-stored", q("meta", meta_a_is_1(), 0), true),
            ("meta-absent", q("meta-absent", meta_a_is_1(), 0), true),
            (
                "meta-deny",
                q(
                    "meta",
                    field_filter("meta.blocked", Op::Equal, bool_value(true)),
                    0,
                ),
                false,
            ),
            ("only-plain", q("only-plain", a_is_1(), 0), true),
            ("only-extra", q("only-extra", a_is_1(), 0), true),
            ("only-b-deny", q("only-b", a_is_1(), 0), false),
            ("size-plain", q("size-plain", a_is_1(), 0), true),
            ("size-extra", q("size-extra", a_is_1(), 0), true),
            ("size-zero-deny", q("size-zero", a_is_1(), 0), false),
            ("name-offset", q("own", own_name("mine"), 1), true),
            ("owner-offset", q("own", owner_filter(&alice), 1), true),
            ("foreign-offset", q("own", own_name("foreign"), 1), false),
            ("fn-resource", q("fn-resource", a_is_1(), 0), true),
            ("fn-null-deny", q("fn-null", a_is_1(), 0), false),
            ("fn-arg-allow", q("fn-arg", a_is_1(), 0), true),
        ];
        for (row, request, allowed) in rows {
            let answer = run(&mut h, request, &token).await;
            assert_eq!(answer.is_ok(), allowed, "{profile} {row}: {answer:?}");
            if !allowed {
                assert_eq!(
                    answer,
                    Err(tonic::Code::PermissionDenied),
                    "{profile} {row}"
                );
            }
        }
        h.handle.abort();
    }
}
