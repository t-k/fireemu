//! Claimed differences from the official Firestore emulator (firebase-tools 15.28.2) in
//! query authorization. Every `#[ignore]`d test states the official answer as reported by a
//! user; each is a claim to check, not recorded production behaviour.

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

fn owner_and_name(uid: &str, id: &str) -> pb::RunQueryRequest {
    let mut request = list("tasks");
    query_mut(&mut request).r#where = Some(and(vec![
        field_filter("owner", sq::field_filter::Operator::Equal, s(uid)),
        field_filter(
            "__name__",
            sq::field_filter::Operator::Equal,
            reference(&format!("tasks/{id}")),
        ),
    ]));
    request
}

// ----------------------------------------------------------------------------------------
// Item 1: owner == uid AND documentId() == name
// ----------------------------------------------------------------------------------------

/// Control: a lone `__name__ ==` query is checked against the named document and refused when
/// the document does not exist (the claim and fireemu agree).
#[tokio::test]
async fn lone_name_query_for_a_missing_document_is_refused() {
    let mut h = start().await;
    let (_alice, token) = h.user("alice@example.com");
    h.rules.replace_source(OWNER_RULES).unwrap();
    let mut request = list("tasks");
    query_mut(&mut request).r#where = Some(field_filter(
        "__name__",
        sq::field_filter::Operator::Equal,
        reference("tasks/missing"),
    ));
    assert_eq!(
        run(&mut h, request, &token).await,
        Err(tonic::Code::PermissionDenied)
    );
    h.handle.abort();
}

#[tokio::test]
#[ignore = "claimed official PERMISSION_DENIED for owner==uid AND __name__==missing; fireemu returns 0 documents: rules-name-plus-filter-query-skips-actual-document.md"]
async fn owner_and_name_query_for_a_missing_document_is_refused() {
    let mut h = start().await;
    let (alice, token) = h.user("alice@example.com");
    h.rules.replace_source(OWNER_RULES).unwrap();
    assert_eq!(
        run(&mut h, owner_and_name(&alice, "missing"), &token).await,
        Err(tonic::Code::PermissionDenied)
    );
    h.handle.abort();
}

#[tokio::test]
#[ignore = "claimed official PERMISSION_DENIED for owner==uid AND __name__==<document owned by bob>; fireemu returns 0 documents: rules-name-plus-filter-query-skips-actual-document.md"]
async fn owner_and_name_query_for_a_document_owned_by_someone_else_is_refused() {
    let mut h = start().await;
    let (alice, token) = h.user("alice@example.com");
    let (bob, _) = h.user("bob@example.com");
    h.client
        .commit(with_bearer(
            commit(vec![set_write("tasks/theirs", &[("owner", s(&bob))])]),
            "owner",
        ))
        .await
        .unwrap();
    h.rules.replace_source(OWNER_RULES).unwrap();
    assert_eq!(
        run(&mut h, owner_and_name(&alice, "theirs"), &token).await,
        Err(tonic::Code::PermissionDenied)
    );
    h.handle.abort();
}

// ----------------------------------------------------------------------------------------
// Item 2: `resource != null &&` guard with where("members.<uid>.role", "in", [...])
// ----------------------------------------------------------------------------------------

fn members_role_in(uid: &str) -> pb::RunQueryRequest {
    let mut request = list("rooms");
    let roles = pb::Value {
        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
            values: vec![s("ADMIN"), s("MEMBER")],
        })),
    };
    query_mut(&mut request).r#where = Some(field_filter(
        &format!("members.{uid}.role"),
        sq::field_filter::Operator::In,
        roles,
    ));
    request
}

const MEMBERS_RULES_UNGUARDED: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /rooms/{id} { allow list: if resource.data.members[request.auth.uid].role in ["ADMIN", "MEMBER"]; }
  }
}"#;

const MEMBERS_RULES_GUARDED: &str = r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /rooms/{id} { allow list: if resource != null && resource.data.members[request.auth.uid].role in ["ADMIN", "MEMBER"]; }
  }
}"#;

/// Control: without the `resource != null` guard both emulators allow.
#[tokio::test]
async fn members_role_in_query_without_the_resource_guard_is_allowed() {
    let mut h = start().await;
    let (alice, token) = h.user("alice@example.com");
    h.rules.replace_source(MEMBERS_RULES_UNGUARDED).unwrap();
    assert_eq!(
        run(&mut h, members_role_in(&alice), &token).await,
        Ok(vec![])
    );
    h.handle.abort();
}

#[tokio::test]
#[ignore = "claimed official ALLOW with the `resource != null` guard; fireemu answers PERMISSION_DENIED: rules-resource-not-null-guard-over-query-resource.md"]
async fn members_role_in_query_with_the_resource_not_null_guard_is_allowed() {
    let mut h = start().await;
    let (alice, token) = h.user("alice@example.com");
    h.rules.replace_source(MEMBERS_RULES_GUARDED).unwrap();
    assert_eq!(
        run(&mut h, members_role_in(&alice), &token).await,
        Ok(vec![])
    );
    h.handle.abort();
}

// ----------------------------------------------------------------------------------------
// Item 5: `!("blocked" in resource.data)` with no filter
// ----------------------------------------------------------------------------------------

/// The tests that pin today's deny: `query_proofs_are_sound_for_shapes_arrays_and_collection_groups`
/// (this file's parent, the `shape` collection under "Map-shape conditions cannot be proven")
/// and `undetermined_values_never_prove_a_condition` in fireemu-core-rules tests/eval.rs.
#[tokio::test]
#[ignore = "claimed official ALLOW for an unfiltered list under `!(\"blocked\" in resource.data)`; fireemu denies and two tests pin that: rules-not-in-resource-data-unfiltered-list.md"]
async fn not_in_resource_data_is_allowed_for_an_unfiltered_query() {
    let mut h = start().await;
    let (_alice, token) = h.user("alice@example.com");
    h.rules
        .replace_source(
            r#"rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /shape/{id} { allow list: if !("blocked" in resource.data); }
  }
}"#,
        )
        .unwrap();
    assert_eq!(run(&mut h, list("shape"), &token).await, Ok(vec![]));
    h.handle.abort();
}
