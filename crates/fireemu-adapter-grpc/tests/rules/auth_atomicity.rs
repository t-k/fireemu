//! Bounded local Standard/Native Rules coverage, not production or SDK parity evidence.

use super::*;
use fireemu_core_auth::claims::CustomClaims;
use fireemu_core_firestore::store::{CommitVersion, Document};

fn snapshot(h: &Harness) -> (CommitVersion, Vec<Document>) {
    h.backend
        .read_unadmitted(
            &Parent {
                project: ProjectId::try_new("demo-app").unwrap(),
                database: DatabaseId::default_database(),
                document: None,
            },
            |db| (db.current_version(), db.documents()),
        )
        .unwrap()
}

async fn begin(h: &mut Harness, token: &str) -> Vec<u8> {
    h.client
        .begin_transaction(with_bearer(
            pb::BeginTransactionRequest {
                database: DB.to_owned(),
                ..Default::default()
            },
            token,
        ))
        .await
        .unwrap()
        .into_inner()
        .transaction
}

async fn rollback(h: &mut Harness, transaction: Vec<u8>, token: &str) {
    h.client
        .rollback(with_bearer(
            pb::RollbackRequest {
                database: DB.to_owned(),
                transaction,
                ..Default::default()
            },
            token,
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn rejected_writes_preserve_all_documents_and_versions_for_each_request_identity() {
    let mut h = start().await;
    let (alice, alice_token) = h.user("alice@example.com");
    let (_, bob_token) = h.user("bob@example.com");
    let profile = format!("profiles/{alice}");
    h.client
        .commit(with_bearer(
            commit(vec![
                set_write(&profile, &[("name", s("Alice"))]),
                set_write("public/sentinel", &[("name", s("untouched"))]),
                set_write("owned/existing", &[("owner", s(&alice))]),
            ]),
            "owner",
        ))
        .await
        .unwrap();
    let before = snapshot(&h);
    let wire_before = h
        .client
        .get_document(with_bearer(get(&profile), "owner"))
        .await
        .unwrap()
        .into_inner();

    // A valid first write must not escape when a later write is forbidden. Begin and
    // read as Alice; the identity of the actual Commit request controls authorization.
    for transactional in [false, true] {
        for token in [None, Some(bob_token.as_str()), Some(alice_token.as_str())] {
            for multiwrite in [false, true] {
                let transaction = if transactional {
                    begin(&mut h, &alice_token).await
                } else {
                    Vec::new()
                };
                if transactional {
                    let mut request = get(&profile);
                    request.consistency_selector =
                        Some(pb::get_document_request::ConsistencySelector::Transaction(
                            transaction.clone(),
                        ));
                    h.client
                        .get_document(with_bearer(request, &alice_token))
                        .await
                        .unwrap();
                }
                let mut writes = Vec::new();
                if multiwrite {
                    writes.push(set_write(
                        "owned/existing",
                        &[("owner", s(&alice)), ("bio", s("pending"))],
                    ));
                    writes.push(set_write("owned/new", &[("owner", s(&alice))]));
                }
                let name = if token == Some(alice_token.as_str()) {
                    "forbidden rename"
                } else {
                    "Alice"
                };
                writes.push(set_write(&profile, &[("name", s(name))]));
                let mut request = commit(writes);
                request.transaction.clone_from(&transaction);
                let request = token.map_or_else(
                    || Request::new(request.clone()),
                    |token| with_bearer(request.clone(), token),
                );
                let error = h.client.commit(request).await.unwrap_err();
                assert_eq!(error.code(), tonic::Code::PermissionDenied);
                assert_eq!(
                    snapshot(&h),
                    before,
                    "transaction={transactional}, multiwrite={multiwrite}"
                );
                assert_eq!(
                    h.client
                        .get_document(with_bearer(get(&profile), "owner"))
                        .await
                        .unwrap()
                        .into_inner(),
                    wire_before
                );
                assert_eq!(
                    h.client
                        .get_document(with_bearer(get("owned/new"), "owner"))
                        .await
                        .unwrap_err()
                        .code(),
                    tonic::Code::NotFound
                );
                if transactional {
                    rollback(&mut h, transaction, &alice_token).await;
                }
            }
        }
    }
    h.handle.abort();
}

const ATOMIC_RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{id} {
      allow create: if request.auth != null
        && request.resource.data.owner == request.auth.uid
        && exists(/databases/$(database)/documents/members/$(request.auth.uid))
        && get(/databases/$(database)/documents/stats/posts).data.owner == request.auth.uid
        && getAfter(/databases/$(database)/documents/stats/posts).data.count
             == get(/databases/$(database)/documents/stats/posts).data.count + 1;
    }
    match /stats/{id} {
      allow read: if request.auth != null && resource.data.owner == request.auth.uid;
      allow update: if request.auth != null && resource.data.owner == request.auth.uid
        && request.resource.data.owner == resource.data.owner
        && request.resource.data.count == resource.data.count + 1;
    }
  }
}";

fn int(value: i64) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::IntegerValue(value)),
    }
}

#[tokio::test]
async fn atomic_rules_read_before_and_final_state_in_batches_and_transactions() {
    for transactional in [false, true] {
        for reverse in [false, true] {
            let mut h = start().await;
            let (alice, token) = h.user("alice@example.com");
            h.rules.replace_source(ATOMIC_RULES).unwrap();
            h.client
                .commit(with_bearer(
                    commit(vec![
                        set_write("stats/posts", &[("owner", s(&alice)), ("count", int(0))]),
                        set_write(
                            "stats/unrelated",
                            &[("owner", s(&alice)), ("count", int(0))],
                        ),
                        set_write(&format!("members/{alice}"), &[("role", s("writer"))]),
                    ]),
                    "owner",
                ))
                .await
                .unwrap();
            // The unrelated counter increment passes its own rule. Only the post
            // getAfter relation denies that case, isolating final-state validation.
            for (permitted, counter, count) in [
                (false, "stats/posts", 2),
                (false, "stats/unrelated", 1),
                (true, "stats/posts", 1),
            ] {
                let before = snapshot(&h);
                let wire_before = h
                    .client
                    .get_document(with_bearer(get(counter), "owner"))
                    .await
                    .unwrap()
                    .into_inner();
                let transaction = if transactional {
                    begin(&mut h, &token).await
                } else {
                    Vec::new()
                };
                let mut writes = vec![
                    set_write("posts/new", &[("owner", s(&alice))]),
                    set_write(counter, &[("owner", s(&alice)), ("count", int(count))]),
                ];
                if reverse {
                    writes.reverse();
                }
                let mut request = commit(writes);
                request.transaction.clone_from(&transaction);
                let result = h.client.commit(with_bearer(request, &token)).await;
                if permitted {
                    let result = result.unwrap().into_inner();
                    assert_eq!(result.write_results.len(), 2);
                    let post = h
                        .client
                        .get_document(with_bearer(get("posts/new"), "owner"))
                        .await
                        .unwrap()
                        .into_inner();
                    let stats = h
                        .client
                        .get_document(with_bearer(get("stats/posts"), "owner"))
                        .await
                        .unwrap()
                        .into_inner();
                    assert_eq!(post.update_time, stats.update_time);
                    assert_eq!(stats.fields["count"], int(1));
                    assert_ne!(snapshot(&h).0, before.0);
                } else {
                    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
                    assert_eq!(snapshot(&h), before);
                    assert_eq!(
                        h.client
                            .get_document(with_bearer(get(counter), "owner"))
                            .await
                            .unwrap()
                            .into_inner(),
                        wire_before
                    );
                    assert_eq!(
                        h.client
                            .get_document(with_bearer(get("posts/new"), "owner"))
                            .await
                            .unwrap_err()
                            .code(),
                        tonic::Code::NotFound
                    );
                    if transactional {
                        rollback(&mut h, transaction, &token).await;
                    }
                }
            }
            h.handle.abort();
        }
    }
}

#[tokio::test]
async fn revoked_and_disabled_tokens_cannot_change_single_batch_or_transaction_state() {
    for disabled in [false, true] {
        let mut h = start().await;
        let (alice, token) = h.user("alice@example.com");
        h.client
            .commit(with_bearer(
                commit(vec![set_write("owned/existing", &[("owner", s(&alice))])]),
                &token,
            ))
            .await
            .unwrap();
        let transaction = begin(&mut h, &token).await;
        let before = snapshot(&h);
        {
            let mut auth = h.auth.lock().unwrap();
            let uid = auth.user_by_id(&alice).unwrap().local_id.clone();
            if disabled {
                auth.user_mut(&uid).unwrap().disabled = true;
            } else {
                auth.revoke_tokens(
                    &uid,
                    LogicalInstant::from_nanos(START.as_nanos() + 1_000_000_000),
                )
                .unwrap();
            }
        }
        for (multiwrite, transactional) in [(false, false), (true, false), (true, true)] {
            let mut writes = vec![set_write(
                "owned/existing",
                &[("owner", s(&alice)), ("bio", s("changed"))],
            )];
            if multiwrite {
                writes.push(set_write("owned/new", &[("owner", s(&alice))]));
            }
            let mut request = commit(writes);
            if transactional {
                request.transaction.clone_from(&transaction);
            }
            assert_eq!(
                h.client
                    .commit(with_bearer(request, &token))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
            assert_eq!(snapshot(&h), before);
        }
        rollback(&mut h, transaction, "owner").await;
        h.handle.abort();
    }
}

#[tokio::test]
async fn tenant_and_custom_claims_authorize_same_uid_without_cross_tenant_access() {
    let mut h = start().await;
    h.rules
        .replace_source(
            r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /tenantDocs/{uid} {
      allow write: if request.auth != null && request.auth.uid == uid
        && request.auth.token.firebase.tenant == 'tenant-a'
        && request.auth.token.writer == true;
    }
  }
}",
        )
        .unwrap();
    // Identical UID makes tenant/claim enforcement necessary: uid checks alone cannot pass.
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                "public/sentinel",
                &[("value", s("untouched"))],
            )]),
            "owner",
        ))
        .await
        .unwrap();
    let mut tokens = Vec::new();
    for tenant in [None, Some("tenant-b"), Some("tenant-a")] {
        let store = tenant.map_or_else(
            || h.auth.clone(),
            |tenant| h.registry.ensure_tenant("demo-app", tenant).unwrap(),
        );
        let mut store = store.lock().unwrap();
        let uid = store
            .create_user_with_id(
                NewUser::email("shared@example.com"),
                Some("shared-user"),
                START,
            )
            .unwrap();
        for writer in [false, true] {
            store
                .set_custom_claims(
                    &uid,
                    CustomClaims::parse_attributes(if writer {
                        r#"{"writer":true}"#
                    } else {
                        r#"{"writer":false}"#
                    })
                    .unwrap(),
                )
                .unwrap();
            tokens.push((
                tenant == Some("tenant-a") && writer,
                encode_unsigned(&store.id_token_claims(&uid, None, START).unwrap()),
            ));
        }
    }
    for (permitted, token) in tokens {
        let before = snapshot(&h);
        let response = h
            .client
            .commit(with_bearer(
                commit(vec![set_write(
                    "tenantDocs/shared-user",
                    &[("value", s("private"))],
                )]),
                &token,
            ))
            .await;
        if permitted {
            response.unwrap();
        } else {
            assert_eq!(response.unwrap_err().code(), tonic::Code::PermissionDenied);
            assert_eq!(snapshot(&h), before);
        }
    }
    h.handle.abort();
}

#[tokio::test]
async fn atomic_rules_refuse_missing_membership_and_preserve_the_preimage() {
    let mut h = start().await;
    let (alice, token) = h.user("alice@example.com");
    h.rules.replace_source(ATOMIC_RULES).unwrap();
    h.client
        .commit(with_bearer(
            commit(vec![set_write(
                "stats/posts",
                &[("owner", s(&alice)), ("count", int(0))],
            )]),
            "owner",
        ))
        .await
        .unwrap();
    for transactional in [false, true] {
        let before = snapshot(&h);
        let transaction = if transactional {
            begin(&mut h, &token).await
        } else {
            Vec::new()
        };
        let mut request = commit(vec![
            set_write("stats/posts", &[("owner", s(&alice)), ("count", int(1))]),
            set_write("posts/new", &[("owner", s(&alice))]),
        ]);
        request.transaction.clone_from(&transaction);
        assert_eq!(
            h.client
                .commit(with_bearer(request, &token))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(snapshot(&h), before);
        if transactional {
            rollback(&mut h, transaction, &token).await;
        }
    }
    h.handle.abort();
}
