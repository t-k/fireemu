//! Exact-union account-query policy tests. These are local, not production observations.
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthStore, NewUser, UserQueryExpression as Expr, UserRecord, UserSortField,
};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

fn fixture() -> AuthStore {
    let mut store = AuthStore::new("demo-query", SplitMix64::new(41), TotpPolicy::default());
    for (id, email, name, phone) in [
        ("a", "alice@example.com", "Z", Some("+15550000001")),
        ("b", "bob@example.com", "A", None),
        ("c", "carol@example.com", "B", Some("+15550000003")),
        ("d", "dave@example.com", "C", None),
    ] {
        let uid = store
            .create_user_with_id(NewUser::email(email), Some(id), LogicalInstant::UNIX_EPOCH)
            .unwrap();
        let user = store.user_mut(&uid).unwrap();
        user.display_name = Some(name.to_owned());
        user.phone_number = phone.map(str::to_owned);
    }
    store
}

fn ids(users: Vec<&UserRecord>) -> Vec<&str> {
    users
        .into_iter()
        .map(|user| user.local_id.as_str())
        .collect()
}

#[test]
fn exact_union_matches_email_phone_and_uid_without_duplicate_users() {
    let store = fixture();
    let filter = [
        Expr::Email("ALICE@EXAMPLE.COM".into()),
        Expr::PhoneNumber("+15550000001".into()),
        Expr::UserId("c".into()),
    ];
    assert_eq!(store.matching_user_count(&filter), 2);
    assert_eq!(
        ids(store.users_matching_sorted_page(&filter, UserSortField::LocalId, 0, 500, false)),
        ["a", "c"]
    );
    assert_eq!(store.matching_user_count(&[]), 4);
}

#[test]
fn filtering_precedes_sort_offset_limit_and_count() {
    let store = fixture();
    let filter = [
        Expr::UserId("a".into()),
        Expr::UserId("c".into()),
        Expr::UserId("d".into()),
    ];
    for (sort, expected) in [
        (UserSortField::LocalId, ["a", "c", "d"]),
        (UserSortField::Name, ["c", "d", "a"]),
    ] {
        for descending in [false, true] {
            let mut expected = expected.to_vec();
            if descending {
                expected.reverse();
            }
            for offset in 0..6 {
                for limit in [0, 1, 2, 500, usize::MAX] {
                    let page: Vec<_> = expected.iter().copied().skip(offset).take(limit).collect();
                    assert_eq!(
                        ids(store
                            .users_matching_sorted_page(&filter, sort, offset, limit, descending)),
                        page
                    );
                }
            }
        }
    }
    assert_eq!(store.matching_user_count(&filter), 3);
}

#[test]
fn empty_partial_wildcard_and_case_changed_uid_are_not_broadened() {
    let store = fixture();
    for filter in [
        Expr::Email(String::new()),
        Expr::Email("alice".into()),
        Expr::Email("%@example.com".into()),
        Expr::UserId("A".into()),
        Expr::PhoneNumber("15550000001".into()),
    ] {
        assert_eq!(store.matching_user_count(std::slice::from_ref(&filter)), 0);
        assert!(store
            .users_matching_sorted_page(&[filter], UserSortField::Name, 0, 500, false)
            .is_empty());
    }
}

#[test]
fn filtering_is_read_only_and_huge_offsets_are_safe() {
    let store = fixture();
    let before = format!("{store:?}");
    let filter = [Expr::Email("ALICE@EXAMPLE.COM".into())];
    for field in [
        UserSortField::Name,
        UserSortField::Email,
        UserSortField::CreatedAt,
        UserSortField::LastLoginAt,
        UserSortField::LocalId,
    ] {
        assert!(store
            .users_matching_sorted_page(&filter, field, usize::MAX, usize::MAX, false)
            .is_empty());
        assert_eq!(
            ids(store.users_matching_sorted_page(&filter, field, 0, 1, true)),
            ["a"]
        );
    }
    assert_eq!(before, format!("{store:?}"));
}

#[test]
fn current_record_values_are_used_without_a_stale_query_index() {
    let mut store = fixture();
    let uid = store.all_user_ids()[0].clone();
    let filter = [Expr::Email("alice@example.com".into())];
    assert_eq!(store.matching_user_count(&filter), 1);
    store.user_mut(&uid).unwrap().email = Some("changed@example.com".into());
    assert_eq!(store.matching_user_count(&filter), 0);
    assert_eq!(
        store.matching_user_count(&[Expr::Email("CHANGED@example.com".into())]),
        1
    );
    store.delete_user_by_id("a").unwrap();
    assert_eq!(store.matching_user_count(&[Expr::UserId("a".into())]), 0);
}
