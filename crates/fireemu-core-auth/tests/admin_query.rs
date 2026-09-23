//! Native account-query ordering tests. Local tie/null policy is not a production receipt.

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser, UserRecord, UserSortField};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const FIELDS: [UserSortField; 5] = [
    UserSortField::LocalId,
    UserSortField::Name,
    UserSortField::CreatedAt,
    UserSortField::LastLoginAt,
    UserSortField::Email,
];

fn empty() -> AuthStore {
    AuthStore::new("demo-query", SplitMix64::new(19), TotpPolicy::default())
}

fn fixture() -> AuthStore {
    let mut store = empty();
    for (id, email, name, created, last_login) in [
        ("c", Some("z@example.com"), Some("Z"), 10, Some(3)),
        ("a", Some("a@example.com"), None, 9, None),
        ("d", Some("d@example.com"), Some(""), 20, Some(10)),
        ("b", Some("b@example.com"), Some("A"), 2, Some(2)),
        ("e", None, Some("名前"), 2, Some(3)),
    ] {
        let user = email.map_or_else(NewUser::anonymous, NewUser::email);
        let uid = store
            .create_user_with_id(user, Some(id), LogicalInstant::from_unix_seconds(created))
            .unwrap();
        let record = store.user_mut(&uid).unwrap();
        record.display_name = name.map(str::to_owned);
        record.last_sign_in_at = last_login.map(LogicalInstant::from_unix_seconds);
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
fn every_field_has_numeric_time_and_deterministic_missing_value_order() {
    let store = fixture();
    let orders = [
        ["a", "b", "c", "d", "e"],
        ["a", "d", "b", "c", "e"],
        ["b", "e", "a", "c", "d"],
        ["a", "b", "c", "e", "d"],
        ["e", "a", "b", "d", "c"],
    ];
    // Descending reverses the field only; ties keep ascending user-id order (sandbox
    // recording 2026-09-23, `auth-account/admin/query#sort-name-desc`).
    let descending_orders = [
        ["e", "d", "c", "b", "a"],
        ["e", "c", "b", "d", "a"],
        ["d", "c", "a", "b", "e"],
        ["d", "c", "e", "b", "a"],
        ["c", "d", "b", "a", "e"],
    ];
    for ((field, expected), descending) in FIELDS.into_iter().zip(orders).zip(descending_orders) {
        assert_eq!(ids(store.users_sorted_page(field, 0, 5, false)), expected);
        assert_eq!(ids(store.users_sorted_page(field, 0, 5, true)), descending);
    }
}

#[test]
fn bounded_pages_equal_slices_of_the_independently_expected_whole_order() {
    let store = fixture();
    let orders = [
        ["a", "b", "c", "d", "e"],
        ["a", "d", "b", "c", "e"],
        ["b", "e", "a", "c", "d"],
        ["a", "b", "c", "e", "d"],
        ["e", "a", "b", "d", "c"],
    ];
    // Descending reverses the field only; ties keep ascending user-id order (sandbox
    // recording 2026-09-23, `auth-account/admin/query#sort-name-desc`).
    let descending_orders = [
        ["e", "d", "c", "b", "a"],
        ["e", "c", "b", "d", "a"],
        ["d", "c", "a", "b", "e"],
        ["d", "c", "e", "b", "a"],
        ["c", "d", "b", "a", "e"],
    ];
    for ((field, order), descending_order) in FIELDS.into_iter().zip(orders).zip(descending_orders)
    {
        for descending in [false, true] {
            let expected = if descending { descending_order } else { order };
            for offset in 0..8 {
                for limit in [0, 1, 2, 5, usize::MAX] {
                    let want: Vec<_> = expected.iter().copied().skip(offset).take(limit).collect();
                    assert_eq!(
                        ids(store.users_sorted_page(field, offset, limit, descending)),
                        want,
                        "{field:?} offset={offset} limit={limit} descending={descending}"
                    );
                }
            }
        }
    }
}

#[test]
fn empty_store_zero_limit_and_huge_offsets_never_allocate_from_request_values() {
    for store in [empty(), fixture()] {
        for field in FIELDS {
            for descending in [false, true] {
                assert!(store.users_sorted_page(field, 0, 0, descending).is_empty());
                assert!(store
                    .users_sorted_page(field, usize::MAX, usize::MAX, descending)
                    .is_empty());
                assert!(store
                    .users_sorted_page(field, usize::MAX - 1, 500, descending)
                    .is_empty());
            }
        }
    }
}

#[test]
fn queries_are_read_only_and_new_field_values_are_not_hidden_by_stale_indexes() {
    let mut store = fixture();
    let before: Vec<_> = store.users_by_creation().into_iter().cloned().collect();
    for field in FIELDS {
        for descending in [false, true] {
            let _ = store.users_sorted_page(field, 1, 2, descending);
        }
    }
    let after: Vec<_> = store.users_by_creation().into_iter().cloned().collect();
    assert_eq!(before, after);

    let uid = store
        .all_user_ids()
        .into_iter()
        .find(|uid| uid.as_str() == "a")
        .unwrap();
    store.user_mut(&uid).unwrap().display_name = Some("ZZ".to_owned());
    store.set_email(&uid, "zz@example.com").unwrap();
    store.record_sign_in(&uid, LogicalInstant::from_unix_seconds(100));
    assert_eq!(
        ids(store.users_sorted_page(UserSortField::Name, 0, 5, false)),
        ["d", "b", "c", "a", "e"]
    );
    assert_eq!(
        ids(store.users_sorted_page(UserSortField::Email, 0, 1, true)),
        ["a"]
    );
    assert_eq!(
        ids(store.users_sorted_page(UserSortField::LastLoginAt, 0, 1, true)),
        ["a"]
    );
    store.delete_user_by_id("a").unwrap();
    assert_eq!(
        ids(store.users_sorted_page(UserSortField::LastLoginAt, 0, 1, true)),
        ["d"]
    );
}

#[test]
fn timestamp_ties_use_exposed_milliseconds_not_hidden_submillisecond_values() {
    let mut store = empty();
    // UID order is opposite to nanosecond order, but both expose millisecond 1.
    let a = store
        .create_user_with_id(
            NewUser::anonymous(),
            Some("a"),
            LogicalInstant::from_nanos(1_999_999),
        )
        .unwrap();
    let b = store
        .create_user_with_id(
            NewUser::anonymous(),
            Some("b"),
            LogicalInstant::from_nanos(1_000_000),
        )
        .unwrap();
    store.user_mut(&a).unwrap().last_sign_in_at = Some(LogicalInstant::from_nanos(2_999_999));
    store.user_mut(&b).unwrap().last_sign_in_at = Some(LogicalInstant::from_nanos(2_000_000));
    for field in [UserSortField::CreatedAt, UserSortField::LastLoginAt] {
        assert_eq!(ids(store.users_sorted_page(field, 0, 2, false)), ["a", "b"]);
        // Equal exposed milliseconds tie, and ties stay in user-id order when descending.
        assert_eq!(ids(store.users_sorted_page(field, 0, 2, true)), ["a", "b"]);
    }
}

#[test]
fn top_page_scans_beyond_the_first_uid_page_and_honors_descending_offset() {
    let mut store = empty();
    for number in 0..128 {
        let uid = store
            .create_user_with_id(
                NewUser::anonymous(),
                Some(&format!("uid-{number:03}")),
                LogicalInstant::from_unix_seconds(number),
            )
            .unwrap();
        store.user_mut(&uid).unwrap().display_name = Some(format!("name-{:03}", 127 - number));
    }
    assert_eq!(
        ids(store.users_sorted_page(UserSortField::Name, 1, 3, false)),
        ["uid-126", "uid-125", "uid-124"]
    );
    assert_eq!(
        ids(store.users_sorted_page(UserSortField::Name, 1, 3, true)),
        ["uid-001", "uid-002", "uid-003"]
    );
}
