//! The order in which the official emulator (firebase-database-emulator v4.11.2) and production
//! hand out the entries of a multi-path write: a REST `PATCH`, a realtime merge (`m`) and the
//! writes registered with `onDisconnect`, which are all kept in a Scala `immutable.Map`.
//!
//! Observed (offline against the jar, and in production for one six-key set): up to four
//! entries come out in insertion order (`Map1` to `Map4`); with five or more the map is a
//! `HashMap` (`HashTrieMap`), which yields them by the hash of the key: `String.hashCode`,
//! mixed by `improve`, then 5-bit chunks from the low bits, each trie level in index order.
//! A map that has held five entries stays a `HashMap` after entries are removed. Entries of a
//! write whose keys are paths (`a/b`) are first gathered into a tree by their first key and so
//! on, and each node's children are ordered this way, depth first.

/// The 32-bit hash of `key` as Java's `String.hashCode` computes it (UTF-16 code units). It is
/// kept as the bit pattern of the `int`, so the arithmetic below wraps like Java's.
fn java_hash(key: &str) -> u32 {
    key.encode_utf16().fold(0u32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(u32::from(unit))
    })
}

/// `scala.collection.immutable.HashMap.improve` (Scala 2.12).
fn improve(hash: u32) -> u32 {
    let mut h = hash.wrapping_add(!(hash << 9));
    h ^= h >> 14;
    h = h.wrapping_add(h << 4);
    h ^ (h >> 10)
}

/// The indices of `keys` (distinct, in insertion order) in the order of a Scala map holding
/// them. `hashed` says the map has been a `HashMap` already: it is one from the fifth entry on.
pub(crate) fn scala_order<K: AsRef<str>>(keys: &[K], hashed: bool) -> Vec<usize> {
    if keys.len() <= 4 && !hashed {
        return (0..keys.len()).collect();
    }
    let items: Vec<(u32, usize)> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (improve(java_hash(key.as_ref())), index))
        .collect();
    let mut out = Vec::with_capacity(items.len());
    trie_order(items, 0, &mut out);
    out
}

/// Walks the trie of `items` (improved hash, index) from `shift` bits up.
fn trie_order(items: Vec<(u32, usize)>, shift: u32, out: &mut Vec<usize>) {
    if items.len() <= 1 || shift >= 35 {
        // One entry, or keys whose whole hash is equal (a collision list, in insertion order).
        out.extend(items.into_iter().map(|(_, index)| index));
        return;
    }
    let mut buckets: Vec<Vec<(u32, usize)>> = vec![Vec::new(); 32];
    for item in items {
        buckets[((item.0 >> shift) & 31) as usize].push(item);
    }
    for bucket in buckets {
        trie_order(bucket, shift + 5, out);
    }
}

/// A node of the tree a multi-path write is gathered into.
#[derive(Default)]
struct Node {
    /// Children in first-appearance order.
    children: Vec<(String, Node)>,
    /// The write ending here.
    leaf: Option<usize>,
}

/// The order of the entries of one multi-path write whose paths are `paths` and whose keys as
/// sent are `raw`: the indices into `paths`. The server keeps the write as a map keyed by the
/// raw key text (`a/x`, hashed as written), gathers it into a tree in that map's order, and
/// lists each node's children as a map again.
pub(crate) fn write_order(raw: &[String], paths: &[Vec<String>]) -> Vec<usize> {
    let mut root = Node::default();
    for index in scala_order(raw, false) {
        let mut node = &mut root;
        for key in &paths[index] {
            let at = if let Some(at) = node.children.iter().position(|(name, _)| name == key) {
                at
            } else {
                node.children.push((key.clone(), Node::default()));
                node.children.len() - 1
            };
            node = &mut node.children[at].1;
        }
        node.leaf.get_or_insert(index);
    }
    let mut out = Vec::with_capacity(paths.len());
    walk(&root, &mut out);
    out
}

fn walk(node: &Node, out: &mut Vec<usize>) {
    out.extend(node.leaf);
    let names: Vec<&str> = node
        .children
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    for index in scala_order(&names, false) {
        walk(&node.children[index].1, out);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{improve, java_hash, scala_order, write_order};
    use proptest::prelude::*;

    /// The recorded orders (see the fixture's provenance).
    pub(crate) fn fixture() -> serde_json::Value {
        let text = include_str!("../tests/fixtures/multi-path-order-official-emulator-4.11.2.json");
        serde_json::from_str(text).unwrap()
    }

    pub(crate) fn strings(value: &serde_json::Value) -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }

    fn ordered(keys: &[String]) -> Vec<String> {
        scala_order(keys, false)
            .into_iter()
            .map(|i| keys[i].clone())
            .collect()
    }

    #[test]
    fn the_hash_is_javas_string_hash_mixed_the_scala_way() {
        assert_eq!(java_hash(""), 0);
        assert_eq!(java_hash("a"), 97);
        assert_eq!(java_hash("e2"), 3_181);
        // Wraps like an int, and counts UTF-16 units: U+1F600 is two.
        assert_eq!(java_hash("marker"), 3_213_661_242);
        assert_eq!(java_hash("\u{1F600}"), 55_357 * 31 + 56_832);
        assert_eq!(improve(0), 4_286_836_480);
        assert_eq!(improve(97), 4_294_388_074);
    }

    #[test]
    fn up_to_four_keys_keep_their_insertion_order() {
        let keys: Vec<String> = ["d", "c", "b", "a"]
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        for n in 0..=4 {
            assert_eq!(ordered(&keys[..n]), keys[..n].to_vec());
        }
        // A map that was a hash map before keeps the hash order.
        assert_eq!(scala_order(&["e2", "e5"], false), vec![0, 1]);
        assert_ne!(scala_order(&["e2", "e5", "e6"], true), vec![0, 1, 2]);
    }

    #[test]
    fn production_five_set_fires_e6_e5_marker_e4_e3_e2() {
        let keys = ["e2", "e3", "e4", "e5", "e6", "marker"];
        let order: Vec<&str> = scala_order(&keys, false)
            .into_iter()
            .map(|i| keys[i])
            .collect();
        assert_eq!(order, ["e6", "e5", "marker", "e4", "e3", "e2"]);
    }

    #[test]
    fn flat_sets_follow_the_recorded_orders() {
        let fixture = fixture();
        let sets = fixture["flat"].as_array().unwrap();
        assert!(sets.len() >= 100);
        for set in sets {
            assert_eq!(
                ordered(&strings(&set["keys"])),
                strings(&set["order"]),
                "{set}"
            );
        }
    }

    #[test]
    fn writes_follow_the_recorded_orders_whatever_the_mode() {
        let fixture = fixture();
        let writes = fixture["writes"].as_array().unwrap();
        assert!(writes.len() >= 40);
        for write in writes {
            assert_eq!(
                ordered(&strings(&write["keys"])),
                strings(&write["order"]),
                "{write}"
            );
        }
    }

    #[test]
    fn paths_are_gathered_by_their_first_key_before_they_are_ordered() {
        let paths: Vec<Vec<String>> = ["p/a", "q", "r/x", "s", "t", "u"]
            .iter()
            .map(|p| p.split('/').map(str::to_owned).collect())
            .collect();
        let order: Vec<String> = write_order(
            &paths.iter().map(|p| p.join("/")).collect::<Vec<_>>(),
            &paths,
        )
        .into_iter()
        .map(|i| paths[i].join("/"))
        .collect();
        // Probed on the jar: s, t, u, q, then the parents p and r (not s, r/x, p/a, t, u, q).
        assert_eq!(order, ["s", "t", "u", "q", "p/a", "r/x"]);
    }

    #[test]
    fn the_order_equals_the_scala_2_12_12_library_on_ascii_non_ascii_and_surrogate_keys() {
        // Differential table from scala-library 2.12.12 in the jar (see the fixture's provenance).
        let text = include_str!("../tests/fixtures/scala-map-order-scala-2.12.12.json");
        let table: serde_json::Value = serde_json::from_str(text).unwrap();
        let sets = table["sets"].as_array().unwrap();
        assert!(sets.len() >= 100);
        assert!(sets
            .iter()
            .any(|s| s["keys"].as_array().unwrap().len() >= 100));
        let mut hashed_sets = 0;
        for set in sets {
            let keys = strings(&set["keys"]);
            assert_eq!(ordered(&keys), strings(&set["order"]), "{set}");
            hashed_sets += usize::from(keys.len() > 4);
        }
        assert!(hashed_sets >= 80);
        // The table covers non-ASCII keys and keys outside the BMP (two UTF-16 units).
        let every_key: Vec<String> = sets.iter().flat_map(|s| strings(&s["keys"])).collect();
        assert!(every_key.iter().any(|k| !k.is_ascii()));
        assert!(every_key
            .iter()
            .any(|k| k.chars().any(|c| u32::from(c) >= 0x1_0000)));
    }

    #[test]
    fn keys_with_one_hash_stay_in_insertion_order() {
        // "Aa" and "BB" have the same String.hashCode; probed on the jar.
        let order = |keys: &[&str]| -> Vec<String> {
            scala_order(keys, false)
                .into_iter()
                .map(|i| keys[i].to_owned())
                .collect()
        };
        assert_eq!(
            order(&["Aa", "BB", "x1", "x2", "x3", "x4"]),
            ["x3", "Aa", "BB", "x2", "x1", "x4"]
        );
        assert_eq!(
            order(&["BB", "Aa", "x1", "x2", "x3", "x4"]),
            ["x3", "BB", "Aa", "x2", "x1", "x4"]
        );
        assert_eq!(
            order(&["x1", "x2", "BB", "x3", "x4", "Aa"]),
            ["x3", "BB", "Aa", "x2", "x1", "x4"]
        );
    }

    /// The second fixture: raw-frame recordings for nested bodies, integer keys, splits and covered listens.
    pub(crate) fn cases() -> serde_json::Value {
        let text =
            include_str!("../tests/fixtures/multi-path-order-cases-official-emulator-4.11.2.json");
        serde_json::from_str(text).unwrap()
    }

    fn paths_of(keys: &[String]) -> Vec<Vec<String>> {
        keys.iter()
            .map(|k| {
                k.split('/')
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .collect()
    }

    fn written(keys: &[String]) -> Vec<String> {
        let paths = paths_of(keys);
        write_order(keys, &paths)
            .into_iter()
            .map(|i| paths[i].join("/"))
            .collect()
    }

    #[test]
    fn the_reviews_four_nested_rows_follow_the_hash_order_of_the_keys_as_sent() {
        let owned = |keys: &[&str]| keys.iter().map(|k| (*k).to_owned()).collect::<Vec<_>>();
        // Order review of 2026-10-27, raw frames on the jar: the order does not depend on the send order.
        assert_eq!(
            written(&owned(&["a/x", "a/y", "b", "c", "d"])),
            ["a/y", "a/x", "b", "c", "d"]
        );
        assert_eq!(
            written(&owned(&["d", "c", "b", "a/y", "a/x"])),
            ["a/y", "a/x", "b", "c", "d"]
        );
        assert_eq!(
            written(&owned(&["zz", "a/x", "a/y", "a/z", "a/w", "a/v"])),
            ["a/x", "a/y", "a/v", "a/w", "a/z", "zz"]
        );
        assert_eq!(
            written(&owned(&["a/x", "a/y", "a/v", "a/w", "a/z", "zz"])),
            ["a/x", "a/y", "a/v", "a/w", "a/z", "zz"]
        );
    }

    #[test]
    fn nested_and_integer_writes_follow_the_recorded_orders_by_patch_and_by_merge() {
        let cases = cases();
        let nested = cases["nested"].as_array().unwrap();
        // Table rows, three spellings the server hashes as written, 40 random nested bodies (by PATCH and by merge).
        assert!(nested.len() >= 90);
        for kind in ["table", "rawSpelling", "random"] {
            assert!(nested.iter().any(|c| c["kind"] == kind), "{kind}");
        }
        for case in nested {
            assert_eq!(
                written(&strings(&case["keys"])),
                strings(&case["order"]),
                "{case}"
            );
        }
        let integers = cases["flatIntegers"].as_array().unwrap();
        assert!(integers.len() >= 8);
        for case in integers {
            assert_eq!(
                written(&strings(&case["keys"])),
                strings(&case["order"]),
                "{case}"
            );
        }
    }

    #[test]
    fn the_server_hashes_the_key_as_it_was_sent_not_the_path_it_names() {
        // 'u//x' names u/x but hashes as written (probed on the jar: u/x, u/y, f, b, d; not f, u/y, u/x, b, d).
        let keys: Vec<String> = ["u//x", "u/y", "b", "f", "d"]
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        assert_eq!(written(&keys), ["u/x", "u/y", "f", "b", "d"]);
        let normalized: Vec<String> = ["u/x", "u/y", "b", "f", "d"]
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        assert_eq!(written(&normalized), ["f", "u/y", "u/x", "b", "d"]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// The order is a permutation; from five keys on it does not depend on the insertion
        /// order, and below that it is the insertion order.
        #[test]
        fn a_permutation_that_five_keys_or_more_do_not_owe_to_insertion(
            keys in prop::collection::btree_set("[a-z0-9]{1,6}", 0..30),
            seed in any::<u64>(),
        ) {
            let keys: Vec<String> = keys.into_iter().collect();
            let hashes: std::collections::BTreeSet<u32> = keys.iter().map(|k| java_hash(k)).collect();
            // Keys with one hash ("Aa" and "BB") stay in insertion order; see the collision test.
            prop_assume!(hashes.len() == keys.len());
            let order = scala_order(&keys, false);
            let mut sorted = order.clone();
            sorted.sort_unstable();
            prop_assert_eq!(sorted, (0..keys.len()).collect::<Vec<_>>());
            if keys.len() >= 5 {
                let mut shuffled = keys.clone();
                let mut state = seed | 1;
                for i in (1..shuffled.len()).rev() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    shuffled.swap(i, usize::try_from(state % (u64::try_from(i).unwrap() + 1)).unwrap());
                }
                prop_assert_eq!(ordered(&shuffled), ordered(&keys));
            } else {
                prop_assert_eq!(order, (0..keys.len()).collect::<Vec<_>>());
            }
        }

        /// A write of single-key paths is ordered as its keys are.
        #[test]
        fn flat_paths_are_ordered_as_keys(keys in prop::collection::btree_set("[a-z0-9]{1,6}", 0..20)) {
            let keys: Vec<String> = keys.into_iter().collect();
            let paths: Vec<Vec<String>> = keys.iter().map(|k| vec![k.clone()]).collect();
            prop_assert_eq!(write_order(&keys, &paths), scala_order(&keys, false));
        }
    }
}
