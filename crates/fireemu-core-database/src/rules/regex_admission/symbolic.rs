//! Count-independent bounded-repetition prototype; not a production admission hook.
//! Nullable copies use suffix thresholds. Nonnullable copies are indexed lazily.
use super::{Automaton, Edge, Failure, Graph, PROTOTYPE_EDGES, State, guard_count, state_bound};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Subset {
    // This root is a separate graph identity, never a language-only equivalence class.
    Root,
    Nullable(Vec<u32>),
    Indexed(Vec<(u32, usize)>),
}

fn target(child: &Graph, state: usize, unit: u16) -> Option<usize> {
    child.states[state]
        .edges
        .iter()
        .find(|e| e.lo <= unit && unit <= e.hi)
        .map(|e| e.to)
}

impl Subset {
    fn units(&self) -> usize {
        match self {
            Self::Root => 1,
            Self::Nullable(thresholds) => thresholds.len(),
            Self::Indexed(states) => states.len() * 2,
        }
    }

    fn accepts(&self, child: &Graph, min: u32, max: u32) -> bool {
        match self {
            Self::Root => min == 0 || child.states[child.initial].accept,
            Self::Nullable(thresholds) => thresholds
                .iter()
                .enumerate()
                .any(|(q, &first)| first < max && child.states[q].accept),
            Self::Indexed(states) => states
                .iter()
                .any(|&(copy, q)| child.states[q].accept && (min == 0 || copy >= min - 1)),
        }
    }

    fn next(&self, child: &Graph, max: u32, unit: u16) -> Result<Self, Failure> {
        match self {
            Self::Root => {
                let destination = target(child, child.initial, unit);
                if child.states[child.initial].accept {
                    let mut thresholds = vec![max; child.states.len()];
                    if let Some(q) = destination {
                        thresholds[q] = 0;
                    }
                    Ok(Self::Nullable(thresholds))
                } else {
                    Ok(Self::Indexed(
                        destination.map(|q| vec![(0, q)]).unwrap_or_default(),
                    ))
                }
            }
            Self::Nullable(thresholds) => {
                let mut next = vec![max; child.states.len()];
                let mut accepting_first = max;
                for (q, &first) in thresholds.iter().enumerate() {
                    if first == max {
                        continue;
                    }
                    if let Some(to) = target(child, q, unit) {
                        next[to] = next[to].min(first);
                    }
                    if child.states[q].accept {
                        accepting_first = accepting_first.min(first);
                    }
                }
                if accepting_first < max {
                    if let Some(to) = target(child, child.initial, unit) {
                        // accepting_first < max <= i32::MAX, so this addition is exact.
                        next[to] = next[to].min(accepting_first + 1);
                    }
                }
                Ok(Self::Nullable(next))
            }
            Self::Indexed(states) => {
                let mut next = BTreeSet::new();
                for &(copy, q) in states {
                    if let Some(to) = target(child, q, unit) {
                        next.insert((copy, to));
                    }
                    if child.states[q].accept && copy + 1 < max {
                        if let Some(to) = target(child, child.initial, unit) {
                            next.insert((copy + 1, to));
                        }
                    }
                    if next.len() > PROTOTYPE_EDGES {
                        return Err(Failure::Inconclusive);
                    }
                }
                Ok(Self::Indexed(next.into_iter().collect()))
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
    state_bound(child.states.len())?;
    let initial = if min == 0 || child.states[child.initial].accept {
        Subset::Root
    } else {
        Subset::Indexed(vec![(0, child.initial)])
    };
    let points = child.points();
    let mut intern = BTreeMap::from([(initial.clone(), 0)]);
    let mut subsets = vec![initial];
    let mut states = vec![State::default()];
    let mut cursor = 0usize;
    let mut edge_count = 0usize;
    let mut units = subsets[0].units();
    while cursor < subsets.len() {
        guard_count(cursor as u64 + 1, threshold)?;
        let subset = subsets[cursor].clone();
        states[cursor].accept = subset.accepts(child, min, max);
        for (i, &lo) in points.iter().enumerate() {
            let next = subset.next(child, max, lo)?;
            let to = if let Some(&to) = intern.get(&next) {
                to
            } else {
                // Every discovered subset will eventually be dequeued. Refusal here is
                // equivalent to the later guard and prevents an unbounded pending queue.
                guard_count(subsets.len() as u64 + 1, threshold)?;
                state_bound(subsets.len() + 1)?;
                units = units
                    .checked_add(next.units())
                    .ok_or(Failure::Inconclusive)?;
                if units > PROTOTYPE_EDGES {
                    return Err(Failure::Inconclusive);
                }
                let to = subsets.len();
                intern.insert(next.clone(), to);
                subsets.push(next);
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
    // Dead-state removal and minimization occur only after the guarded traversal.
    Ok((
        Automaton::Graph(Graph {
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

pub(super) fn count_only(
    child: &Graph,
    min: u32,
    max: u32,
    threshold: u64,
) -> Result<Option<u64>, Failure> {
    construct(child, min, max, threshold).map(|(_, count)| count)
}
