//! Symbolic minimum-repeat prototype retaining the unminimized star-tail identities.
use super::{Automaton, Edge, Failure, Graph, PROTOTYPE_EDGES, State, guard_count, state_bound};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Prefix {
    Root,
    None,
    Nullable(Vec<(usize, u32)>),
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

    fn units(&self) -> usize {
        self.tail.len()
            + match &self.prefix {
                Prefix::None | Prefix::Root => 1,
                Prefix::Nullable(v) => v.len() * 2,
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
                .any(|&(q, first)| first < min && child.states[q].accept),
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
                    if child.states[q].accept {
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
    let mut cursor = 0;
    let mut units = keys[0].units();
    let mut edge_count = 0;
    while cursor < keys.len() {
        guard_count(cursor as u64 + 1, threshold)?;
        let current = keys[cursor].clone();
        states[cursor].accept = current.accepts(child, min);
        let points = current.points(child, min);
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
            if let Some(last) = states[cursor].edges.last_mut() {
                if last.to == to && u32::from(last.hi) + 1 == u32::from(lo) {
                    last.hi = hi;
                    continue;
                }
            }
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
