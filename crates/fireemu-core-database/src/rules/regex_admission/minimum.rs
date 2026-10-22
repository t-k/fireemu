//! Symbolic minimum-repeat prototype retaining the unminimized star-tail identities.
use super::{Automaton, Edge, Failure, Graph, PROTOTYPE_EDGES, State, guard_count, state_bound};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Prefix {
    Root,
    None,
    Nullable(Vec<u32>),
    Indexed(Vec<(u32, usize)>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    prefix: Prefix,
    // The child states in the tail retain their identities; this is not a minimized star.
    tail: Vec<usize>,
}

fn target(child: &Graph, state: usize, unit: u16) -> Option<usize> {
    child.states[state]
        .edges
        .iter()
        .find(|e| e.lo <= unit && unit <= e.hi)
        .map(|e| e.to)
}

impl Key {
    fn units(&self) -> usize {
        self.tail.len()
            + match &self.prefix {
                Prefix::None | Prefix::Root => 1,
                Prefix::Nullable(v) => v.len(),
                Prefix::Indexed(v) => v.len() * 2,
            }
    }

    fn accepts(&self, child: &Graph, min: u32) -> bool {
        if self.tail.iter().any(|&q| child.states[q].accept) {
            return true;
        }
        match &self.prefix {
            Prefix::Root => min == 0 || child.states[child.initial].accept,
            Prefix::None => false,
            Prefix::Nullable(v) => v
                .iter()
                .enumerate()
                .any(|(q, &first)| first < min && child.states[q].accept),
            Prefix::Indexed(v) => v
                .iter()
                .any(|&(copy, q)| copy + 1 == min && child.states[q].accept),
        }
    }

    fn next(&self, child: &Graph, min: u32, unit: u16) -> Result<Self, Failure> {
        let start_target = target(child, child.initial, unit);
        let mut tail = BTreeSet::new();
        for &q in &self.tail {
            if let Some(to) = target(child, q, unit) {
                tail.insert(to);
            }
            if child.states[q].accept {
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
                    let mut thresholds = vec![min; child.states.len()];
                    if let Some(to) = start_target {
                        thresholds[to] = 0;
                    }
                    Prefix::Nullable(thresholds)
                }
            }
            Prefix::None => Prefix::None,
            Prefix::Nullable(v) => {
                let mut thresholds = vec![min; child.states.len()];
                let mut first_accept = min;
                for (q, &first) in v.iter().enumerate() {
                    if first == min {
                        continue;
                    }
                    if let Some(to) = target(child, q, unit) {
                        thresholds[to] = thresholds[to].min(first);
                    }
                    if child.states[q].accept {
                        first_accept = first_accept.min(first);
                    }
                }
                if first_accept < min {
                    if let Some(to) = start_target {
                        thresholds[to] = thresholds[to].min(first_accept + 1);
                        // Every active nullable prefix accept can reach the star tail.
                        tail.insert(to);
                    }
                }
                Prefix::Nullable(thresholds)
            }
            Prefix::Indexed(v) => {
                let mut next = BTreeSet::new();
                for &(copy, q) in v {
                    if let Some(to) = target(child, q, unit) {
                        next.insert((copy, to));
                    }
                    if child.states[q].accept {
                        if let Some(to) = start_target {
                            if copy + 1 < min {
                                next.insert((copy + 1, to));
                            } else {
                                tail.insert(to);
                            }
                        }
                    }
                    if next.len() > PROTOTYPE_EDGES {
                        return Err(Failure::Inconclusive);
                    }
                }
                Prefix::Indexed(next.into_iter().collect())
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
    state_bound(child.states.len())?;
    let prefix = if min == 0 || child.states[child.initial].accept {
        Prefix::Root
    } else {
        // A nonnullable initial self-loop can revisit this actual indexed subset.
        Prefix::Indexed(vec![(0, child.initial)])
    };
    let initial = Key {
        prefix,
        tail: Vec::new(),
    };
    let mut intern = BTreeMap::from([(initial.clone(), 0)]);
    let mut keys = vec![initial];
    let mut states = vec![State::default()];
    let points = child.points();
    let mut cursor = 0;
    let mut units = keys[0].units();
    let mut edge_count = 0;
    while cursor < keys.len() {
        guard_count(cursor as u64 + 1, threshold)?;
        let current = keys[cursor].clone();
        states[cursor].accept = current.accepts(child, min);
        for (i, &lo) in points.iter().enumerate() {
            let next = current.next(child, min, lo)?;
            let to = if let Some(&to) = intern.get(&next) {
                to
            } else {
                guard_count(keys.len() as u64 + 1, threshold)?;
                state_bound(keys.len() + 1)?;
                units = units
                    .checked_add(next.units())
                    .ok_or(Failure::Inconclusive)?;
                if units > PROTOTYPE_EDGES {
                    return Err(Failure::Inconclusive);
                }
                let to = keys.len();
                intern.insert(next.clone(), to);
                keys.push(next);
                states.push(State::default());
                to
            };
            let hi = points.get(i + 1).map_or(u16::MAX, |&p| p - 1);
            states[cursor].edges.push(Edge { lo, hi, to });
            edge_count += 1;
            if edge_count > PROTOTYPE_EDGES {
                return Err(Failure::Inconclusive);
            }
        }
        cursor += 1;
    }
    Ok((
        Automaton::Graph(Graph {
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
