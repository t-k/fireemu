//! `PartitionQuery` as production answers it (FS-QUERY-INDEX partition-query rows, recorded
//! 2026-09-24 on `fireemu-oracle-query/(default)`).
//!
//! Production splits a collection group at sampled document keys: about one key in 141 is a
//! sample (14 of 2,000 documents), a request for `partition_count` cursors gets that many
//! samples (all of them when there are fewer) chosen in a fixed priority order, so a smaller
//! count returns a subset of a larger one, and the cursors come back in key order. A small
//! group has no sample and so no cursor. Which keys production samples comes from a hash over
//! its internal key encoding that could not be recovered (FS-QUERY-INDEX closure scope
//! decision on partition cursor positions); fireemu samples with its own stable hash of the
//! document name, so the shape matches and the positions differ.

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Query, QueryScope};

/// One key in this many is a partition sample.
const SAMPLE_ONE_IN: u64 = 141;

/// FNV-1a over `salt` then the document's relative path.
fn key_hash(path: &DocumentPath, salt: &[u8]) -> u64 {
    salt.iter()
        .chain(path.relative().as_bytes())
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

/// Whether the sampler picks `path` as a partition point (a test builds a group that splits
/// from such names).
#[must_use]
pub fn is_sample(path: &DocumentPath) -> bool {
    key_hash(path, b"sample") % SAMPLE_ONE_IN == 0
}

/// The partition cursors for `count` over the group's documents: the `count` samples first in
/// priority order, in key order.
#[must_use]
pub fn partition_cursors(paths: &[DocumentPath], count: usize) -> Vec<DocumentPath> {
    let mut samples: Vec<(u64, &DocumentPath)> = paths
        .iter()
        .filter(|path| is_sample(path))
        .map(|path| (key_hash(path, b"priority"), path))
        .collect();
    samples.sort();
    let mut chosen: Vec<DocumentPath> = samples
        .into_iter()
        .take(count)
        .map(|(_, path)| path.clone())
        .collect();
    chosen.sort();
    chosen
}

/// Production's refusal of a partition count that is not positive.
pub const COUNT_NOT_POSITIVE: &str = "Partition count must be greater than zero.";
/// Production's refusal of a negative page size.
pub const PAGE_SIZE_NEGATIVE: &str = "Page size must be nonnegative.";
/// Production's refusal of a page token it cannot read.
pub const TOKEN_UNREADABLE: &str = "invalid page token";
/// Production's refusal of a page token issued for another request.
pub const TOKEN_FOREIGN: &str = "Invalid page token.";
/// Production's refusal of a parent below the database.
pub const ANCESTOR_QUERY: &str = "Ancestor queries are not supported.";

/// What production answers for an accepted query's shape: a refusal (its text), no partition
/// at all (a kindless query, or one without an explicit order), or `Ok(true)` to split it.
pub fn check_query(query: &Query) -> Result<bool, &'static str> {
    let refusal = match &query.scope {
        QueryScope::KindlessAllDescendants { .. } => return Ok(false),
        // Without `allDescendants`, as for a collection (partition-query/refusals
        // #not-collection-group).
        QueryScope::Collection { .. } | QueryScope::KindlessChildren { .. } => {
            Some("Query must select all descendant collections.")
        }
        QueryScope::CollectionGroup { .. } => None,
    }
    .or_else(|| {
        query
            .limit
            .is_some()
            .then_some("Query limit is not supported.")
    })
    .or_else(|| (query.offset != 0).then_some("Query offset is not supported."))
    // A projection is refused only by production: fireemu partitioned such a query before, and
    // the emulator profile adds no rejection.
    .or_else(|| {
        (query.projection.is_some() && query.production_refusals)
            .then_some("Property masks are not supported.")
    })
    .or_else(|| {
        query
            .start_at
            .is_some()
            .then_some("Query start cursors are not supported.")
    })
    .or_else(|| {
        query
            .end_at
            .is_some()
            .then_some("Query end cursors are not supported.")
    });
    if let Some(refusal) = refusal {
        return Err(refusal);
    }
    Ok(!query.order_by.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_types::ids::{DatabaseId, ProjectId};

    fn paths(count: usize) -> Vec<DocumentPath> {
        let project = ProjectId::try_new("p").unwrap();
        let database = DatabaseId::try_new("(default)").unwrap();
        let mut out: Vec<DocumentPath> = (0..count)
            .map(|i| {
                DocumentPath::parse(&project, &database, &format!("qroot/r{}/qp/d{i:05}", i % 3))
                    .unwrap()
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn a_large_group_splits_at_about_one_key_in_141_and_counts_nest() {
        let group = paths(2000);
        let all = partition_cursors(&group, usize::MAX);
        assert!((8..=22).contains(&all.len()), "{}", all.len());
        let mut previous: Vec<DocumentPath> = Vec::new();
        for count in [1, 2, 3, 4, 8, 64] {
            let cursors = partition_cursors(&group, count);
            assert_eq!(cursors.len(), count.min(all.len()));
            assert!(
                cursors.windows(2).all(|pair| pair[0] < pair[1]),
                "key order"
            );
            assert!(previous.iter().all(|path| cursors.contains(path)), "nested");
            previous = cursors;
        }
        assert_eq!(partition_cursors(&group, 8), partition_cursors(&group, 8));
    }

    #[test]
    fn only_a_query_over_all_descendants_is_split() {
        let children = Query::new(QueryScope::kindless_children(None));
        assert_eq!(
            check_query(&children),
            Err("Query must select all descendant collections.")
        );
        let kindless = Query::new(QueryScope::kindless_all_descendants(None));
        assert_eq!(check_query(&kindless), Ok(false));
    }

    #[test]
    fn a_small_group_has_no_sample() {
        let project = ProjectId::try_new("p").unwrap();
        let database = DatabaseId::try_new("(default)").unwrap();
        let small: Vec<DocumentPath> = (0..5)
            .map(|i| {
                DocumentPath::parse(&project, &database, &format!("qroot/r{}/qp/s{i}", i % 2))
                    .unwrap()
            })
            .collect();
        assert!(partition_cursors(&small, 64).is_empty());
        assert!(partition_cursors(&[], 2).is_empty());
    }
}
