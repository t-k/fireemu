//! Count-independent bounded repetition for load-time admission.
//! Nullable copies use suffix thresholds. Nonnullable copies are indexed lazily.
use super::{
    guard_count, push_item, reserve_items, Automaton, Edge, Failure, Graph, State, SubsetIndex,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Subset {
    // This root is a separate graph identity, never a language-only equivalence class.
    Root,
    Nullable(Vec<(usize, u32)>),
    Indexed(Vec<(u32, usize)>),
}

fn target(child: &Graph, state: usize, unit: u16) -> Option<usize> {
    child
        .outgoing(state)
        .find(|e| e.lo <= unit && unit <= e.hi)
        .map(|e| e.to)
}

// Missing entries are exactly the old sentinel `max`, not an omitted copy.
fn lower(next: &mut BTreeMap<usize, u32>, q: usize, first: u32, bound: u32) {
    if first < bound {
        let old = next.entry(q).or_insert(first);
        *old = (*old).min(first);
    }
}

impl Subset {
    fn points(&self, child: &Graph, max: u32) -> Vec<u16> {
        // Cross-copy resets may use the child initial state. Including it even
        // when inactive only subdivides equal successor intervals.
        let mut sources = BTreeSet::from([child.initial]);
        match self {
            Self::Root => {}
            Self::Nullable(v) => sources.extend(
                v.iter()
                    .filter_map(|&(q, first)| (first < max).then_some(q)),
            ),
            Self::Indexed(v) => sources.extend(v.iter().map(|&(_, q)| q)),
        }
        child.points_for(sources)
    }

    fn accepts(&self, child: &Graph, min: u32, max: u32) -> bool {
        match self {
            Self::Root => min == 0 || child.accepts(child.initial),
            Self::Nullable(thresholds) => thresholds
                .iter()
                .any(|&(q, first)| first < max && child.accepts(q)),
            Self::Indexed(states) => states
                .iter()
                .any(|&(copy, q)| child.accepts(q) && (min == 0 || copy >= min - 1)),
        }
    }

    fn next(&self, child: &Graph, max: u32, unit: u16) -> Result<Self, Failure> {
        match self {
            Self::Root => {
                let destination = target(child, child.initial, unit);
                if child.accepts(child.initial) {
                    Ok(Self::Nullable(
                        destination.map(|q| vec![(q, 0)]).unwrap_or_default(),
                    ))
                } else {
                    Ok(Self::Indexed(
                        destination.map(|q| vec![(0, q)]).unwrap_or_default(),
                    ))
                }
            }
            Self::Nullable(thresholds) => {
                let mut next = BTreeMap::new();
                let mut accepting_first = max;
                for &(q, first) in thresholds {
                    if let Some(to) = target(child, q, unit) {
                        lower(&mut next, to, first, max);
                    }
                    if child.accepts(q) {
                        accepting_first = accepting_first.min(first);
                    }
                }
                if accepting_first < max {
                    if let Some(to) = target(child, child.initial, unit) {
                        lower(&mut next, to, accepting_first + 1, max);
                    }
                }
                Ok(Self::Nullable(next.into_iter().collect()))
            }
            Self::Indexed(states) => {
                let mut next = Vec::new();
                for &(copy, q) in states {
                    if let Some(to) = target(child, q, unit) {
                        push_item(&mut next, (copy, to))?;
                    }
                    if child.accepts(q) && copy + 1 < max {
                        if let Some(to) = target(child, child.initial, unit) {
                            push_item(&mut next, (copy + 1, to))?;
                        }
                    }
                }
                next.sort_unstable();
                next.dedup();
                Ok(Self::Indexed(next))
            }
        }
    }
}

// Preserve constructor tags and deterministic shortcuts before attempting any guard.
fn construct(
    child: &Graph,
    min: u32,
    max: u32,
    threshold: u64,
) -> Result<(Automaton, Option<u64>), Failure> {
    if min > i32::MAX as u32 || max > i32::MAX as u32 {
        return Err(Failure::Integer);
    }
    if !child.deterministic {
        return Err(Failure::Inconclusive);
    }
    if min > max {
        return Ok((Automaton::Graph(Graph::empty()), None));
    }
    if max == 0 {
        return Ok((Automaton::Singleton(Vec::new()), None));
    }
    if min == 1 && max == 1 {
        return Ok((Automaton::Graph(child.clone()), None));
    }
    // List concatenation returns the deterministic empty automaton immediately.
    // A later optional suffix forces the false flag again, even if unreachable.
    if min > 1 && min == max && child.accepting().is_empty() {
        return Ok((Automaton::Graph(Graph::empty()), None));
    }
    // Readers query exact logical IDs and reachable accepting states sparsely;
    // total namespace cardinality is not a canonical resource guard.
    let initial = if min == 0 || child.accepts(child.initial) {
        Subset::Root
    } else {
        Subset::Indexed(vec![(0, child.initial)])
    };
    let mut subsets = vec![initial];
    let mut intern = SubsetIndex::default();
    intern.insert(SubsetIndex::digest(&subsets[0]), 0)?;
    let mut states = vec![State::default()];
    let mut cursor = 0usize;
    while cursor < subsets.len() {
        guard_count(cursor as u64 + 1, threshold)?;
        states[cursor].accept = subsets[cursor].accepts(child, min, max);
        let points = subsets[cursor].points(child, max);
        for (i, &lo) in points.iter().enumerate() {
            let next = subsets[cursor].next(child, max, lo)?;
            let digest = SubsetIndex::digest(&next);
            let to = if let Some(to) = intern.find(digest, &next, &subsets) {
                to
            } else {
                // Every discovered subset will eventually be dequeued. Refusal here is
                // equivalent to the later guard and prevents an unbounded pending queue.
                guard_count(subsets.len() as u64 + 1, threshold)?;
                reserve_items(&mut subsets, 1)?;
                reserve_items(&mut states, 1)?;
                let to = subsets.len();
                intern.insert(digest, to)?;
                subsets.push(next);
                states.push(State::default());
                to
            };
            let hi = points.get(i + 1).map_or(u16::MAX, |&p| p - 1);
            if let Some(last) = states[cursor].edges.last_mut() {
                if last.to == to && u32::from(last.hi) + 1 == u32::from(lo) {
                    last.hi = hi;
                    continue;
                }
            }
            reserve_items(&mut states[cursor].edges, 1)?;
            states[cursor].edges.push(Edge { lo, hi, to });
        }
        cursor += 1;
    }
    // Dead-state removal and minimization occur only after the guarded traversal.
    Ok((
        Automaton::Graph(Graph {
            word: None,
            store: None,
            states,
            initial: 0,
            deterministic: true,
        }),
        Some(cursor as u64),
    ))
}

pub(super) fn bounded(
    child: &Graph,
    min: u32,
    max: u32,
    threshold: u64,
) -> Result<(Automaton, Option<u64>), Failure> {
    let (mut value, count) = construct(child, min, max, threshold)?;
    value.minimize(threshold)?;
    Ok((value, count))
}

#[cfg(test)]
pub(super) fn count_only(
    child: &Graph,
    min: u32,
    max: u32,
    threshold: u64,
) -> Result<Option<u64>, Failure> {
    construct(child, min, max, threshold).map(|(_, count)| count)
}

#[test]
fn typed_key_collision_preserves_symbolic_construction_identities() {
    let keys: Vec<Subset> = vec![
        Subset::Root,
        Subset::Nullable(vec![]),
        Subset::Indexed(vec![]),
        Subset::Nullable(vec![(1, 0)]),
        Subset::Nullable(vec![(1, 1)]),
        Subset::Indexed(vec![(0, 1)]),
        Subset::Indexed(vec![(1, 1)]),
    ];
    let mut index = SubsetIndex::default();
    for id in 0..keys.len() {
        index.insert(7, id).unwrap();
    }
    for (id, key) in keys.iter().enumerate() {
        assert_eq!(index.find(7, key, &keys), Some(id));
    }
}

#[test]
fn indexed_scratch_failure_refuses_before_any_successor_is_installed() {
    let child = super::tests::finite_prefix_nonnullable_hole_child();
    let current = Subset::Indexed(vec![(0, 1), (1, 1)]);
    for budget in 0..4 {
        let _fault = super::AllocationFault::after(budget);
        assert_eq!(current.next(&child, 4, 97), Err(Failure::Allocation));
    }
    let _fault = super::AllocationFault::after(4);
    assert!(current.next(&child, 4, 97).is_ok());
}

#[test]
fn indexed_copy_holes_remain_exact_after_four_units() {
    let child = super::tests::finite_prefix_nonnullable_hole_child();
    let mut key = Subset::Indexed(vec![(0, 0)]);
    for _ in 0..4 {
        key = key.next(&child, 4, 97).unwrap();
    }
    let Subset::Indexed(pairs) = key else {
        panic!("nonnullable copy key changed kind")
    };
    let copies: Vec<_> = pairs
        .into_iter()
        .filter_map(|(copy, q)| (q == 1).then_some(copy))
        .collect();
    assert_eq!(copies, vec![1, 3]);
}

#[test]
fn indexed_pairs_cross_former_two_million_boundary_exactly() {
    let child = super::tests::odd_length_a_child();
    // Direct local set evolution, not a full regex witness before the5002 guard.
    for entries in [999_999, 1_000_000, 1_000_001] {
        let current = Subset::Indexed((0..entries).map(|i| (2 * i, 1)).collect());
        let Subset::Indexed(next) = current.next(&child, 2 * entries, 97).unwrap() else {
            panic!("indexed key kind changed")
        };
        assert_eq!(next.len(), 2 * entries as usize);
        for (i, &(copy, q)) in next.iter().enumerate() {
            assert_eq!((copy as usize, q), (i, i % 2));
        }
    }
}
