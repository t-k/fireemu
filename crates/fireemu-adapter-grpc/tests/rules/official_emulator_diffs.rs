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
/// answer is not recorded; the official emulator allows it. Each branch is authorized on its
/// own (the named branch by its document, the other by its constraint proof), so both profiles
/// allow it as the official emulator does; a branch neither check proves refuses.
#[tokio::test]
async fn each_branch_of_an_or_is_authorized_on_its_own() {
    for (profile, mut h) in start_profiles().await {
        let (alice, token) = seed_tasks(&mut h).await;
        let either = |second: sq::Filter| tasks_where(Some(or(vec![name_filter("mine"), second])));
        assert_eq!(
            run(&mut h, either(owner_filter(&alice)), &token).await,
            Ok(vec![doc_name("tasks/mine")]),
            "{profile} or-named-unnamed"
        );
        assert_eq!(
            run(&mut h, either(owner_filter("other-owner")), &token).await,
            Err(tonic::Code::PermissionDenied),
            "{profile} a branch the filters do not prove"
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
/// rule. A reference-valued filter on another field names nothing, and an offset (not
/// recorded) keeps the constraint proof beside the named document.
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
                // With an offset the constraint proof is also required.
                let mut offset = tasks_where(filter);
                query_mut(&mut offset).offset = 1;
                let with_offset = allowed && (named.is_none() || owner == Some(alice.as_str()));
                assert_eq!(
                    run(&mut h, offset, &token).await.is_ok(),
                    with_offset,
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
