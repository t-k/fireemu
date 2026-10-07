//! Opaque production cursors with a retained resource-name boundary.
use std::collections::BTreeMap;

use crate::{PubSubError, Result};

/// A page selected from a resource-name-ordered collection.
#[derive(Debug, PartialEq, Eq)]
pub struct Page<T> {
    /// Resources selected for this page.
    pub resources: Vec<T>,
    /// Empty when the current collection is exhausted.
    pub next_page_token: String,
}

/// Issued cursors retain their boundary after the referenced resource is deleted.
/// The catalogue is shared by adapter clones, has their lifetime, and grants no access.
#[derive(Debug, Default)]
pub struct CursorCatalog {
    anchors: BTreeMap<String, String>,
}

impl CursorCatalog {
    /// Selects an exclusive page boundary from the current collection.
    ///
    /// # Errors
    /// Rejects an out-of-range size or a token without a known resource boundary.
    pub fn paginate<T>(
        &mut self,
        resources: Vec<T>,
        page_size: i32,
        page_token: &str,
        name: impl Fn(&T) -> String,
    ) -> Result<Page<T>> {
        if !(0..=1000).contains(&page_size) {
            return Err(PubSubError::invalid_argument(format!(
                "The value for page_size is out of bounds. You passed {page_size} in the request, but the value must be between 0 and 1000."
            )));
        }
        let limit = if page_size == 0 {
            usize::MAX
        } else {
            usize::try_from(page_size).expect("positive size")
        };
        let start = if page_token.is_empty() {
            0
        } else {
            let anchor = self
                .anchors
                .get(page_token)
                .cloned()
                .or_else(|| {
                    resources
                        .iter()
                        .map(&name)
                        .find(|n| opaque_token(n) == page_token)
                })
                .ok_or_else(|| {
                    PubSubError::invalid_argument(format!(
                        "Invalid page token given (token={page_token})."
                    ))
                })?;
            resources.partition_point(|r| name(r) <= anchor)
        };
        let end = start.saturating_add(limit).min(resources.len());
        let next_page_token = if end < resources.len() {
            let anchor = name(&resources[end - 1]);
            let token = opaque_token(&anchor);
            self.anchors.insert(token.clone(), anchor);
            token
        } else {
            String::new()
        };
        Ok(Page {
            resources: resources.into_iter().skip(start).take(limit).collect(),
            next_page_token,
        })
    }
}

// Cursor identity is stable by full resource name and independent of the list route.
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
            token.push(char::from(
                ALPHABET[usize::try_from((bits >> (18 - index * 6)) & 63).expect("six-bit index")],
            ));
        }
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn names(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("projects/demo/topics/topic-{i:03}"))
            .collect()
    }

    proptest! {
        #[test]
        fn pages_partition_current_reference(count in 0usize..80, size in 1i32..20) {
            let expected = names(count);
            let mut catalogue = CursorCatalog::default();
            let mut actual = Vec::new();
            let mut cursor = String::new();
            for _ in 0..=count {
                let page = catalogue.paginate(expected.clone(), size, &cursor, Clone::clone).unwrap();
                prop_assert!(page.resources.len() <= usize::try_from(size).unwrap());
                actual.extend(page.resources);
                cursor = page.next_page_token;
                if cursor.is_empty() {break;}
            }
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn deleted_issued_boundary_and_current_insertions_match_reference(count in 2usize..50, index in 0usize..48, actions in prop::collection::vec((any::<bool>(),0usize..60),0..30)) {
            let mut current: std::collections::BTreeSet<_> = names(count).into_iter().collect();
            let index = index.min(count - 2);
            let anchor = names(count)[index].clone();
            let mut catalogue = CursorCatalog::default();
            let token = catalogue.paginate(current.iter().cloned().collect(), i32::try_from(index + 1).unwrap(), "", Clone::clone).unwrap().next_page_token;
            current.remove(&anchor);
            for (insert, id) in actions {
                let name = format!("projects/demo/topics/topic-{id:03}");
                if insert {current.insert(name);} else {current.remove(&name);}
                let page = catalogue.paginate(current.iter().cloned().collect(), 0, &token, Clone::clone).unwrap();
                let expected: Vec<_> = current.iter().filter(|name| **name > anchor).cloned().collect();
                prop_assert_eq!(page.resources, expected);
                prop_assert!(page.next_page_token.is_empty());
            }
        }

        #[test]
        fn cursor_format_and_size_bounds(name in ".{0,300}", size in any::<i32>()) {
            let token = opaque_token(&name);
            prop_assert_eq!(token.len(),26);
            prop_assert!(token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
            prop_assert_eq!(&token,&opaque_token(&name));
            let mut catalogue=CursorCatalog::default();
            prop_assert_eq!(catalogue.paginate(names(2),size,"",Clone::clone).is_ok(),(0..=1000).contains(&size));
            prop_assert!(catalogue.paginate(names(0),0,"garbage",Clone::clone).is_err());
            let zero=catalogue.paginate(names(2),0,"",Clone::clone).unwrap();
            prop_assert_eq!(zero.resources,names(2));prop_assert!(zero.next_page_token.is_empty());
        }

        #[test]
        fn cursor_same_boundary_is_independent_of_page_size(count in 2usize..50, index in 1usize..49) {
            let index=index.min(count-1);
            let mut catalogue=CursorCatalog::default();
            let direct=catalogue.paginate(names(count),i32::try_from(index).unwrap(),"",Clone::clone).unwrap().next_page_token;
            let mut token=String::new();
            for _ in 0..index {token=catalogue.paginate(names(count),1,&token,Clone::clone).unwrap().next_page_token;}
            prop_assert_eq!(token,direct);
        }
    }
}
