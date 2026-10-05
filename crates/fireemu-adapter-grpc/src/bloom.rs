//! The bloom filter of an existence filter (`unchanged_names`), as the Web SDK reads it.
//!
//! Production sent one with an existence filter when a client resumed a target and gave an expected
//! count (L1b, both recordings): every such answer with a diff carried a bloom filter of the names of
//! the documents the target matches. The SDK uses it to find the documents it holds that the server
//! no longer has: for each key it holds it asks `might_contain` of the document's resource name, and
//! removes the key when the answer is no.
//!
//! The algorithm is the SDK's (`@firebase/firestore` 4.17.1, `BloomFilter`): `md5` of the UTF-8
//! name, the first eight bytes `h1` and the next eight `h2` as little-endian `u64`, and for
//! `i` in `0..hash_count` the bit `(h1 + i * h2) mod 2^64 mod bit_count`, where the bit count is the
//! bitmap's bits minus the padding; bit `n` is `bitmap[n / 8] & (1 << (n % 8))`. The vectors in
//! `tests/fixtures/sdk-bloom-vectors.json` are produced by the SDK's own class
//! (`conformance/src/fs-listen/sdk-bloom.mjs`) and the tests below require this module to equal them.
//!
//! The sizes are derived from the recordings, not read from them. The L1 and L1b recordings state
//! the bitmap only as the length of its base64 text (4, 8 and 12 characters, which allow 1 to 3,
//! 4 to 6 and 7 to 9 bytes), with the padding (7, 3 and 5) and the hash count (12, 13 and 14) for
//! one, two and three documents. A bloom filter's hash count is the rounded optimum
//! `k = bits / n * ln 2`, and for each count exactly one candidate size gives the recorded `k`:
//! 3 bytes (17 bits, 11.8 rounds to 12), 5 bytes (37 bits, 12.8 rounds to 13) and 8 bytes (59 bits,
//! 13.6 rounds to 14). The 6 and 9 bytes the base64 length also allows would give 16 and 15 hashes.
//! The test `the_sizes_are_the_only_ones_that_fit_the_recorded_hash_counts_and_base64_lengths`
//! encodes that relation. Nothing is recorded for another count, so `for_documents` has no filter
//! for it and the caller sends none.

use fireemu_proto_firestore::google::firestore::v1 as pb;
use md5::{Digest, Md5};

/// The documents a filter is recorded for, with the hash count, bitmap bytes and padding.
const RECORDED: [(usize, i32, usize, i32); 3] = [(1, 12, 3, 7), (2, 13, 5, 3), (3, 14, 8, 5)];

/// A bloom filter over document resource names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bloom {
    hash_count: i32,
    bitmap: Vec<u8>,
    padding: i32,
}

impl Bloom {
    /// An empty filter of the given size.
    pub(crate) fn with_size(hash_count: i32, bytes: usize, padding: i32) -> Self {
        Self {
            hash_count,
            bitmap: vec![0; bytes],
            padding,
        }
    }

    /// The filter production sent for exactly these names, or `None` for a count it was not
    /// recorded for (zero, or more than three).
    pub(crate) fn for_documents(names: &[String]) -> Option<Self> {
        let (_, hash_count, bytes, padding) = RECORDED
            .iter()
            .copied()
            .find(|(count, ..)| *count == names.len())?;
        let mut bloom = Self::with_size(hash_count, bytes, padding);
        for name in names {
            bloom.insert(name);
        }
        Some(bloom)
    }

    fn bit_count(&self) -> u64 {
        let bits = u64::try_from(self.bitmap.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(8);
        bits.saturating_sub(u64::try_from(self.padding).unwrap_or(0))
    }

    /// The bit indices of `name`: `(h1 + i * h2)` over 64 bits, modulo the bit count.
    fn indices(&self, name: &str) -> Vec<usize> {
        let bits = self.bit_count();
        if bits == 0 {
            return Vec::new();
        }
        let digest = Md5::digest(name.as_bytes());
        let h1 = u64::from_le_bytes(digest[0..8].try_into().expect("eight bytes"));
        let h2 = u64::from_le_bytes(digest[8..16].try_into().expect("eight bytes"));
        let hashes = u64::try_from(self.hash_count).unwrap_or(0);
        (0..hashes)
            .map(|i| {
                usize::try_from(h1.wrapping_add(i.wrapping_mul(h2)) % bits)
                    .expect("a bit index fits")
            })
            .collect()
    }

    pub(crate) fn insert(&mut self, name: &str) {
        for index in self.indices(name) {
            self.bitmap[index / 8] |= 1 << (index % 8);
        }
    }

    /// The SDK's membership check: whether every bit of `name` is set. An empty filter contains
    /// nothing. The daemon only builds filters; the check is for the tests that hold it to the SDK.
    #[cfg(test)]
    pub(crate) fn might_contain(&self, name: &str) -> bool {
        self.bit_count() > 0
            && self
                .indices(name)
                .iter()
                .all(|index| self.bitmap[index / 8] & (1 << (index % 8)) != 0)
    }

    /// The message production's filter is carried in.
    pub(crate) fn into_proto(self) -> pb::BloomFilter {
        pb::BloomFilter {
            bits: Some(pb::BitSequence {
                bitmap: self.bitmap,
                padding: self.padding,
            }),
            hash_count: self.hash_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "{b:02x}").expect("a string accepts writes");
            out
        })
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/sdk-bloom-vectors.json"))
            .expect("the vectors are JSON")
    }

    #[test]
    fn it_builds_the_bitmaps_and_gives_the_answers_of_the_sdks_own_bloom_filter() {
        let vectors = vectors();
        let all = vectors["vectors"].as_array().unwrap();
        assert!(all.len() >= 40);
        for vector in all {
            let hash_count = i32::try_from(vector["hashCount"].as_i64().unwrap()).unwrap();
            let bytes = usize::try_from(vector["bytes"].as_u64().unwrap()).unwrap();
            let padding = i32::try_from(vector["padding"].as_i64().unwrap()).unwrap();
            let mut bloom = Bloom::with_size(hash_count, bytes, padding);
            for name in vector["names"].as_array().unwrap() {
                bloom.insert(name.as_str().unwrap());
            }
            assert_eq!(
                hex(&bloom.bitmap),
                vector["bitmap"].as_str().unwrap(),
                "{vector}"
            );
            for probe in vector["probes"].as_array().unwrap() {
                let name = probe[0].as_str().unwrap();
                assert_eq!(
                    bloom.might_contain(name),
                    probe[1].as_bool().unwrap(),
                    "{name} in {vector}"
                );
            }
        }
    }

    #[test]
    fn it_has_a_filter_for_the_counts_production_recorded_and_for_no_other() {
        let names = |n: usize| {
            (0..n)
                .map(|i| format!("p/d/documents/r/{i}"))
                .collect::<Vec<_>>()
        };
        for (count, hash_count, bytes, padding) in RECORDED {
            let bloom = Bloom::for_documents(&names(count)).expect("recorded");
            assert_eq!(bloom.hash_count, hash_count);
            assert_eq!(bloom.bitmap.len(), bytes);
            assert_eq!(bloom.padding, padding);
        }
        assert_eq!(Bloom::for_documents(&names(0)), None);
        assert_eq!(Bloom::for_documents(&names(4)), None);
        assert_eq!(Bloom::for_documents(&names(40)), None);
    }

    /// The relation the sizes are derived from: for each recorded count the chosen byte count is
    /// the only candidate whose bit count gives the recorded hash count under `round(bits / n *
    /// ln 2)`, and its base64 text has the recorded length (4, 8 and 12 characters).
    #[test]
    fn the_sizes_are_the_only_ones_that_fit_the_recorded_hash_counts_and_base64_lengths() {
        // round(bits / n * ln 2) in integers, with ln 2 as 693147 / 1_000_000.
        let hashes = |bytes: usize, padding: i32, documents: usize| -> i32 {
            let bits = u64::try_from(bytes * 8).unwrap() - u64::try_from(padding).unwrap();
            let n = u64::try_from(documents).unwrap();
            i32::try_from((bits * 693_147 + n * 500_000) / (n * 1_000_000)).unwrap()
        };
        let base64_length = |bytes: usize| bytes.div_ceil(3) * 4;
        for ((documents, hash_count, bytes, padding), text) in RECORDED.into_iter().zip([4, 8, 12])
        {
            assert_eq!(hashes(bytes, padding, documents), hash_count);
            assert_eq!(base64_length(bytes), text);
            // The other sizes with the same base64 length, at the recorded padding, do not fit.
            let fits: Vec<usize> = (1..=9)
                .filter(|candidate| {
                    base64_length(*candidate) == text
                        && hashes(*candidate, padding, documents) == hash_count
                })
                .collect();
            assert_eq!(fits, vec![bytes], "{documents} documents");
        }
        // The near misses named by the review: 6 and 9 bytes give 16 and 15 hashes.
        assert_eq!(hashes(6, 3, 2), 16);
        assert_eq!(hashes(9, 5, 3), 15);
    }

    #[test]
    fn an_empty_filter_contains_nothing_and_inserting_into_it_does_nothing() {
        let mut bloom = Bloom::with_size(0, 0, 0);
        bloom.insert("x");
        assert!(!bloom.might_contain("x"));
        let mut all_padding = Bloom::with_size(3, 1, 8);
        all_padding.insert("x");
        assert!(!all_padding.might_contain("x"));
        assert_eq!(all_padding.bitmap, vec![0]);
    }

    #[test]
    fn it_carries_its_size_in_the_message() {
        let bloom = Bloom::for_documents(&["a".to_owned(), "b".to_owned()]).unwrap();
        let message = bloom.clone().into_proto();
        assert_eq!(message.hash_count, 13);
        let bits = message.bits.unwrap();
        assert_eq!(bits.padding, 3);
        assert_eq!(bits.bitmap, bloom.bitmap);
    }

    proptest! {
        /// Whatever the names, every document of the filter is accepted (no false negative, which
        /// is what the SDK relies on: a document the server has is never dropped), and the same
        /// names give the same filter in any order.
        #[test]
        fn the_filter_accepts_exactly_the_documents_it_was_built_from_never_dropping_one(
            names in proptest::collection::btree_set("[a-z]{1,6}/[A-Za-z0-9 ü日]{1,8}", 1..=3),
        ) {
            let names: Vec<String> = names
                .into_iter()
                .map(|n| format!("projects/p/databases/(default)/documents/{n}"))
                .collect();
            let bloom = Bloom::for_documents(&names).expect("recorded count");
            for name in &names {
                prop_assert!(bloom.might_contain(name), "{name}");
            }
            let mut reversed = names.clone();
            reversed.reverse();
            prop_assert_eq!(Bloom::for_documents(&reversed), Some(bloom));
        }
    }
}
