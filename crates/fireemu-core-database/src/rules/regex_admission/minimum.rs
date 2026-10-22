//! Symbolic minimum-repeat prototype retaining the unminimized star-tail identities.
use super::{
    Automaton, Edge, Failure, Graph, State, SubsetIndex, guard_count, push_item, reserve_items,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Prefix {
    Root,
    None,
    Nullable(Vec<(usize, u32)>),
    Indexed(Vec<(u32, usize)>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Key {
    prefix: Prefix,
    // The child states in the tail retain their identities; this is not a minimized star.
    tail: Vec<usize>,
}

fn target(child: &Graph, state: usize, unit: u16) -> Option<usize> {
    child
        .outgoing(state)
        .find(|e| e.lo <= unit && unit <= e.hi)
        .map(|e| e.to)
}

fn lower(next: &mut BTreeMap<usize, u32>, q: usize, first: u32, bound: u32) {
    if first < bound {
        let old = next.entry(q).or_insert(first);
        *old = (*old).min(first);
    }
}

impl Key {
    fn points(&self, child: &Graph, min: u32) -> Vec<u16> {
        let mut sources = BTreeSet::from([child.initial]);
        sources.extend(self.tail.iter().copied());
        match &self.prefix {
            Prefix::Root | Prefix::None => {}
            Prefix::Nullable(v) => sources.extend(
                v.iter()
                    .filter_map(|&(q, first)| (first < min).then_some(q)),
            ),
            Prefix::Indexed(v) => sources.extend(v.iter().map(|&(_, q)| q)),
        }
        child.points_for(sources)
    }

    fn accepts(&self, child: &Graph, min: u32) -> bool {
        if self.tail.iter().any(|&q| child.accepts(q)) {
            return true;
        }
        match &self.prefix {
            Prefix::Root => min == 0 || child.accepts(child.initial),
            Prefix::None => false,
            Prefix::Nullable(v) => v.iter().any(|&(q, first)| first < min && child.accepts(q)),
            Prefix::Indexed(v) => v
                .iter()
                .any(|&(copy, q)| copy + 1 == min && child.accepts(q)),
        }
    }

    fn next(&self, child: &Graph, min: u32, unit: u16) -> Result<Self, Failure> {
        let start_target = target(child, child.initial, unit);
        let mut tail = BTreeSet::new();
        for &q in &self.tail {
            if let Some(to) = target(child, q, unit) {
                tail.insert(to);
            }
            if child.accepts(q) {
                if let Some(to) = start_target {
                    tail.insert(to);
                }
            }
        }
        let prefix = match &self.prefix {
            Prefix::Root => {
                if let Some(to) = start_target {
                    tail.insert(to);
                }
                if min == 0 {
                    Prefix::None
                } else {
                    // Positive root mode is used only for a nullable child.
                    Prefix::Nullable(start_target.map(|q| vec![(q, 0)]).unwrap_or_default())
                }
            }
            Prefix::None => Prefix::None,
            Prefix::Nullable(v) => {
                let mut thresholds = BTreeMap::new();
                let mut first_accept = min;
                for &(q, first) in v {
                    if let Some(to) = target(child, q, unit) {
                        lower(&mut thresholds, to, first, min);
                    }
                    if child.accepts(q) {
                        first_accept = first_accept.min(first);
                    }
                }
                if first_accept < min {
                    if let Some(to) = start_target {
                        lower(&mut thresholds, to, first_accept + 1, min);
                        tail.insert(to);
                    }
                }
                Prefix::Nullable(thresholds.into_iter().collect())
            }
            Prefix::Indexed(v) => {
                let mut next = Vec::new();
                for &(copy, q) in v {
                    if let Some(to) = target(child, q, unit) {
                        push_item(&mut next, (copy, to))?;
                    }
                    if child.accepts(q) {
                        if let Some(to) = start_target {
                            if copy + 1 < min {
                                push_item(&mut next, (copy + 1, to))?;
                            } else {
                                tail.insert(to);
                            }
                        }
                    }
                }
                next.sort_unstable();
                next.dedup();
                Prefix::Indexed(next)
            }
        };
        Ok(Self {
            prefix,
            tail: tail.into_iter().collect(),
        })
    }
}

fn construct(child: &Graph, min: u32, threshold: u64) -> Result<(Automaton, Option<u64>), Failure> {
    if min > i32::MAX as u32 {
        return Err(Failure::Integer);
    }
    if !child.deterministic {
        return Err(Failure::Inconclusive);
    }
    // Positive minimum concatenation returns deterministic empty before the guard.
    if min > 0 && child.accepting().is_empty() {
        return Ok((Automaton::Graph(Graph::empty()), None));
    }
    // Readers query exact logical IDs and reachable accepting states sparsely;
    // total namespace cardinality is not a canonical resource guard.
    let prefix = if min == 0 || child.accepts(child.initial) {
        Prefix::Root
    } else {
        // A nonnullable initial self-loop can revisit this actual indexed subset.
        Prefix::Indexed(vec![(0, child.initial)])
    };
    let initial = Key {
        prefix,
        tail: Vec::new(),
    };
    let mut keys = vec![initial];
    let mut intern = SubsetIndex::default();
    intern.insert(SubsetIndex::digest(&keys[0]), 0)?;
    let mut states = vec![State::default()];
    let mut cursor = 0;
    while cursor < keys.len() {
        guard_count(cursor as u64 + 1, threshold)?;
        states[cursor].accept = keys[cursor].accepts(child, min);
        let points = keys[cursor].points(child, min);
        for (i, &lo) in points.iter().enumerate() {
            let next = keys[cursor].next(child, min, lo)?;
            let digest = SubsetIndex::digest(&next);
            let to = if let Some(to) = intern.find(digest, &next, &keys) {
                to
            } else {
                guard_count(keys.len() as u64 + 1, threshold)?;
                reserve_items(&mut keys, 1)?;
                reserve_items(&mut states, 1)?;
                let to = keys.len();
                intern.insert(digest, to)?;
                keys.push(next);
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

pub(super) fn compile(
    child: &Graph,
    min: u32,
    threshold: u64,
) -> Result<(Automaton, Option<u64>), Failure> {
    let (mut value, count) = construct(child, min, threshold)?;
    value.minimize(threshold)?;
    Ok((value, count))
}

pub(super) fn count_only(child: &Graph, min: u32, threshold: u64) -> Result<Option<u64>, Failure> {
    construct(child, min, threshold).map(|(_, count)| count)
}

#[test]
fn typed_key_collision_preserves_minimum_construction_identities() {
    let keys: Vec<Key> = vec![
        Key {
            prefix: Prefix::Root,
            tail: vec![],
        },
        Key {
            prefix: Prefix::None,
            tail: vec![],
        },
        Key {
            prefix: Prefix::Nullable(vec![(1, 0)]),
            tail: vec![],
        },
        Key {
            prefix: Prefix::Nullable(vec![(1, 1)]),
            tail: vec![],
        },
        Key {
            prefix: Prefix::Nullable(vec![(1, 0)]),
            tail: vec![1],
        },
        Key {
            prefix: Prefix::Indexed(vec![(0, 1)]),
            tail: vec![],
        },
        Key {
            prefix: Prefix::Indexed(vec![(1, 1)]),
            tail: vec![],
        },
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
fn indexed_prefix_scratch_failure_is_operational_allocation() {
    let child = super::tests::finite_prefix_nonnullable_hole_child();
    let current = Key {
        prefix: Prefix::Indexed(vec![(0, 1), (1, 1)]),
        tail: vec![],
    };
    for budget in 0..4 {
        let _fault = super::AllocationFault::after(budget);
        assert_eq!(current.next(&child, 4, 97), Err(Failure::Allocation));
    }
    let _fault = super::AllocationFault::after(4);
    assert!(current.next(&child, 4, 97).is_ok());
}
