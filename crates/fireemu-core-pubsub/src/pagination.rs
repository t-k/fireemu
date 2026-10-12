//! Pagination policies for production and the pinned official emulator.

use crate::Result;

/// Which recorded list behavior a transport exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingPolicy {
    /// Production uses opaque cursors after the last returned resource.
    Strict,
    /// The official emulator uses inclusive lexical resource-name cursors.
    Emulator,
}

/// A selected page and its continuation cursor.
#[derive(Debug, PartialEq, Eq)]
pub struct Page<T> {
    /// Resources selected for this page.
    pub resources: Vec<T>,
    /// Empty on exhaustion; otherwise the policy-specific cursor.
    pub next_page_token: String,
}

/// Selects a page from a resource-name-ordered collection.
pub fn paginate<T>(
    resources: Vec<T>,
    page_size: i32,
    page_token: &str,
    policy: PagingPolicy,
    name: impl Fn(&T) -> String,
) -> Result<Page<T>> {
    paginate_after(resources, page_size, page_token, policy, name, None)
}

pub(crate) fn paginate_after<T>(
    resources: Vec<T>,
    page_size: i32,
    page_token: &str,
    policy: PagingPolicy,
    name: impl Fn(&T) -> String,
    issued_boundary: Option<&str>,
) -> Result<Page<T>> {
    let limit = match policy {
        PagingPolicy::Strict => {
            if !(0..=1000).contains(&page_size) {
                return Err(crate::PubSubError::invalid_argument(format!(
                    "The value for page_size is out of bounds. You passed {page_size} in the request, but the value must be between 0 and 1000."
                )));
            }
            if page_size == 0 {
                usize::MAX
            } else {
                usize::try_from(page_size).expect("positive page size")
            }
        }
        PagingPolicy::Emulator => {
            if page_size <= 0 {
                1000
            } else {
                usize::try_from(page_size).expect("positive page size")
            }
        }
    };
    let start = if page_token.is_empty() {
        0
    } else {
        match policy {
            PagingPolicy::Strict => resources
                .iter()
                .position(|r| opaque_token(&name(r)) == page_token)
                .map(|i| i + 1)
                .or_else(|| {
                    issued_boundary.map(|boundary| {
                        resources
                            .iter()
                            .position(|resource| name(resource).as_str() > boundary)
                            .unwrap_or(resources.len())
                    })
                })
                .ok_or_else(|| {
                    crate::PubSubError::invalid_argument(format!(
                        "Invalid page token given (token={page_token})."
                    ))
                })?,
            PagingPolicy::Emulator => resources
                .iter()
                .position(|r| name(r).as_str() >= page_token)
                .unwrap_or(resources.len()),
        }
    };
    let end = start.saturating_add(limit).min(resources.len());
    let next_page_token = if end < resources.len() {
        match policy {
            PagingPolicy::Strict => opaque_token(&name(&resources[end - 1])),
            PagingPolicy::Emulator => name(&resources[end]),
        }
    } else {
        String::new()
    };
    Ok(Page {
        resources: resources.into_iter().skip(start).take(limit).collect(),
        next_page_token,
    })
}

// Cursor values are opaque, stable by resource name and independent of the list route.
// They do not authenticate requests or grant access to resources.
fn opaque_token(name: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 19];
    for (index, seed) in [
        0xcbf2_9ce4_8422_2325u64,
        0x8422_2325_cbf2_9ce4,
        0x9e37_79b9_7f4a_7c15,
    ]
    .into_iter()
    .enumerate()
    {
        let hash = name.bytes().fold(seed, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
        let offset = index * 8;
        let count = (bytes.len() - offset).min(8);
        bytes[offset..offset + count].copy_from_slice(&hash.to_be_bytes()[..count]);
    }
    let mut token = String::with_capacity(26);
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..=chunk.len() {
            let value = (bits >> (18 - index * 6)) & 63;
            token.push(char::from(
                ALPHABET[usize::try_from(value).expect("six-bit index")],
            ));
        }
    }
    token
}

#[cfg(test)]
mod tests {
    use super::{paginate, PagingPolicy};
    use proptest::prelude::*;

    fn names(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("projects/p/subscriptions/sub-{i:03}"))
            .collect()
    }

    #[test]
    fn strict_rejects_negative_size_and_unknown_token_with_recorded_messages() {
        let error = paginate(names(3), -1, "", PagingPolicy::Strict, Clone::clone).unwrap_err();
        assert_eq!(error.message(), "The value for page_size is out of bounds. You passed -1 in the request, but the value must be between 0 and 1000.");
        let error =
            paginate(names(0), 0, "garbage", PagingPolicy::Strict, Clone::clone).unwrap_err();
        assert_eq!(error.message(), "Invalid page token given (token=garbage).");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn issued_deleted_cursor_is_scoped_and_reset_owned() {
        let mut state = crate::PubSubState::new(1);
        let all = names(3);
        let context = "projects/p/subscriptions";
        let token = state
            .paginate(
                context,
                all.clone(),
                1,
                "",
                PagingPolicy::Strict,
                Clone::clone,
            )
            .unwrap()
            .next_page_token;
        let remaining = all[1..].to_vec();
        let exhausted = state
            .paginate(
                context,
                Vec::<String>::new(),
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone,
            )
            .unwrap();
        assert!(exhausted.resources.is_empty());
        assert!(exhausted.next_page_token.is_empty());
        for foreign in [
            "projects/q/subscriptions",
            "projects/p/topics",
            "projects/p/topics/t/subscriptions",
        ] {
            assert!(state
                .paginate(
                    foreign,
                    remaining.clone(),
                    1,
                    &token,
                    PagingPolicy::Strict,
                    Clone::clone
                )
                .is_err());
            // Existing live-member compatibility is independent of issuing list context.
            assert_eq!(
                state
                    .paginate(
                        foreign,
                        all.clone(),
                        1,
                        &token,
                        PagingPolicy::Strict,
                        Clone::clone
                    )
                    .unwrap()
                    .resources,
                vec![all[1].clone()]
            );
        }
        assert!(state
            .paginate(
                context,
                remaining.clone(),
                1,
                "garbage",
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_err());
        state.clear_project("q");
        assert!(state
            .paginate(
                context,
                remaining.clone(),
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_ok());
        state.clear_project("p");
        assert!(state
            .paginate(
                context,
                remaining.clone(),
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_err());
        let token = state
            .paginate(
                context,
                all.clone(),
                1,
                "",
                PagingPolicy::Strict,
                Clone::clone,
            )
            .unwrap()
            .next_page_token;
        state.clear();
        assert!(state
            .paginate(
                context,
                remaining,
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_err());
    }

    #[test]
    fn topic_recreation_retires_related_history_and_project_predicate_reset_clears_history_only_projects(
    ) {
        let mut state = crate::PubSubState::new(1);
        let topic = crate::TopicName::new("p", "parent").unwrap();
        state
            .create_topic(topic.clone(), std::collections::BTreeMap::new())
            .unwrap();
        let context = "projects/p/topics/parent/subscriptions";
        let all = names(3);
        let token = state
            .paginate(
                context,
                all.clone(),
                1,
                "",
                PagingPolicy::Strict,
                Clone::clone,
            )
            .unwrap()
            .next_page_token;
        state.delete_topic(&topic).unwrap();
        state
            .create_topic(topic, std::collections::BTreeMap::new())
            .unwrap();
        assert!(state
            .paginate(
                context,
                all[1..].to_vec(),
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_err());
        let token = state
            .paginate(
                "projects/q/subscriptions",
                all.clone(),
                1,
                "",
                PagingPolicy::Strict,
                Clone::clone,
            )
            .unwrap()
            .next_page_token;
        state.clear_projects_where(|project| project == "q");
        assert!(state
            .paginate(
                "projects/q/subscriptions",
                all[1..].to_vec(),
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_err());
    }

    #[test]
    fn emulator_pages_do_not_register_strict_deleted_boundaries() {
        let mut state = crate::PubSubState::new(1);
        let all = names(3);
        state
            .paginate(
                "projects/p/subscriptions",
                all.clone(),
                1,
                "",
                PagingPolicy::Emulator,
                Clone::clone,
            )
            .unwrap();
        let token = super::opaque_token(&all[0]);
        assert!(state
            .paginate(
                "projects/p/subscriptions",
                all[1..].to_vec(),
                1,
                &token,
                PagingPolicy::Strict,
                Clone::clone
            )
            .is_err());
    }

    proptest! {
        #[test]
        fn issued_deleted_cursor_matches_current_name_reference(
            count in 2usize..40, boundary_index in 0usize..38,
            actions in prop::collection::vec((any::<bool>(), 0usize..60), 0..60), size in 0i32..12,
        ) {
            let mut state = crate::PubSubState::new(1);
            let all = names(count);
            let index = boundary_index.min(count - 2);
            let boundary = all[index].clone();
            let token = state.paginate("projects/p/subscriptions", all.clone(), i32::try_from(index + 1).unwrap(), "", PagingPolicy::Strict, Clone::clone).unwrap().next_page_token;
            let mut live: std::collections::BTreeSet<_> = all.into_iter().collect();
            for (insert, id) in actions {
                let name = format!("projects/p/subscriptions/sub-{id:03}");
                if insert {live.insert(name);} else {live.remove(&name);}
            }
            live.remove(&boundary);
            let expected: Vec<_> = live.iter().filter(|name| *name > &boundary).cloned().collect();
            let page = state.paginate("projects/p/subscriptions", live.into_iter().collect(), size, &token, PagingPolicy::Strict, Clone::clone).unwrap();
            let limit = if size == 0 {expected.len()} else {usize::try_from(size).unwrap()};
            prop_assert_eq!(page.resources, expected.iter().take(limit).cloned().collect::<Vec<_>>());
            prop_assert_eq!(page.next_page_token.is_empty(), expected.len() <= limit);
        }

        #[test]
        fn stateless_deleted_cursor_refuses_strict_but_uses_emulator_name_boundary(count in 2usize..30, index in 0usize..28) {
            let mut resources = names(count);
            let index = index.min(count - 2);
            let deleted = resources[index].clone();
            let cursor = paginate(resources.clone(), i32::try_from(index + 1).unwrap(), "", PagingPolicy::Strict, Clone::clone).unwrap().next_page_token;
            resources.remove(index);
            let error = paginate(resources.clone(), 1, &cursor, PagingPolicy::Strict, Clone::clone).unwrap_err();
            prop_assert_eq!(error.message(), format!("Invalid page token given (token={cursor})."));
            let page = paginate(resources.clone(), 0, &deleted, PagingPolicy::Emulator, Clone::clone).unwrap();
            let expected: Vec<_> = resources.into_iter().filter(|name| name >= &deleted).collect();
            prop_assert_eq!(page.resources, expected);
        }
        #[test]
        fn opaque_cursor_format_is_stable_for_arbitrary_names(name in ".{0,300}") {
            let token = super::opaque_token(&name);
            prop_assert_eq!(token.len(), 26);
            prop_assert!(token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
            prop_assert_eq!(token, super::opaque_token(&name));
        }

        #[test]
        fn strict_pages_partition_the_reference_model(count in 0usize..80, size in 1i32..20) {
            let expected = names(count);
            let mut actual = Vec::new();
            let mut token = String::new();
            for _ in 0..=count {
                let page = paginate(expected.clone(), size, &token, PagingPolicy::Strict, Clone::clone).unwrap();
                prop_assert!(page.resources.len() <= usize::try_from(size).unwrap());
                if !page.next_page_token.is_empty() {
                    prop_assert!((22..=26).contains(&page.next_page_token.len()));
                    prop_assert!(page.next_page_token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
                    let all_remaining = paginate(expected.clone(), 0, &token, PagingPolicy::Strict, Clone::clone).unwrap();
                    prop_assert_eq!(&page.resources, &all_remaining.resources[..page.resources.len()]);
                }
                actual.extend(page.resources);
                token = page.next_page_token;
                if token.is_empty() { break; }
            }
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn strict_cursor_depends_on_last_name_not_page_size(count in 2usize..80, cursor in 1usize..30) {
            let expected = names(count);
            let cursor = cursor.min(count - 1);
            let large = paginate(expected.clone(), i32::try_from(cursor).unwrap(), "", PagingPolicy::Strict, Clone::clone).unwrap();
            let mut token = String::new();
            for _ in 0..cursor {
                token = paginate(expected.clone(), 1, &token, PagingPolicy::Strict, Clone::clone).unwrap().next_page_token;
            }
            prop_assert_eq!(large.next_page_token, token);
        }

        #[test]
        fn strict_size_bounds_are_enforced(size in any::<i32>()) {
            let result = paginate(names(2), size, "", PagingPolicy::Strict, Clone::clone);
            prop_assert_eq!(result.is_ok(), (0..=1000).contains(&size));
        }

        #[test]
        fn strict_zero_returns_every_resource(count in 0usize..80) {
            let expected = names(count);
            let page = paginate(expected.clone(), 0, "", PagingPolicy::Strict, Clone::clone).unwrap();
            prop_assert_eq!(page.resources, expected);
            prop_assert!(page.next_page_token.is_empty());
        }

        #[test]
        fn emulator_inclusive_name_cursor_matches_reference(count in 0usize..80, size in -3i32..25, cursor in 0usize..90) {
            let all = names(count);
            let token = format!("projects/p/subscriptions/sub-{cursor:03}");
            let limit = if size > 0 { usize::try_from(size).unwrap() } else { 1000 };
            let expected: Vec<_> = all.iter().filter(|n| **n >= token).take(limit).cloned().collect();
            let remaining: Vec<_> = all.iter().filter(|n| **n >= token).cloned().collect();
            let page = paginate(all, size, &token, PagingPolicy::Emulator, Clone::clone).unwrap();
            prop_assert_eq!(page.resources, expected);
            prop_assert_eq!(page.next_page_token, remaining.get(limit).cloned().unwrap_or_default());
        }

        #[test]
        fn current_state_pages_follow_insert_delete_model(actions in prop::collection::vec((0u8..3,0usize..30), 0..60), size in 1i32..10) {
            let mut model = std::collections::BTreeSet::new();
            for (action, id) in actions {
                let name = format!("projects/p/topics/topic-{id:03}");
                if action == 0 {model.remove(&name);} else {model.insert(name);}
                let expected: Vec<_> = model.iter().cloned().collect();
                let mut actual = Vec::new();
                let mut token = String::new();
                for _ in 0..=expected.len() {
                    let page = paginate(expected.clone(), size, &token, PagingPolicy::Strict, Clone::clone).unwrap();
                    actual.extend(page.resources);
                    token = page.next_page_token;
                    if token.is_empty() {break;}
                }
                prop_assert_eq!(actual, expected);
            }
        }
    }
}
