//! Sparse complete-DFA block refinement; guard observations precede this pass.
use super::{Edge, Graph, State};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn intervals(mut row: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    row.sort_unstable();
    let mut result: Vec<(u16, u16)> = Vec::new();
    for (lo, hi) in row {
        if let Some(last) = result.last_mut() {
            if u32::from(lo) <= u32::from(last.1) + 1 {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        result.push((lo, hi));
    }
    result
}

pub(super) fn refine(graph: &mut Graph) {
    // Certified chain suffixes have distinct lengths and residual languages.
    if graph.word.is_some() {
        return;
    }
    let dead = graph.states.len();
    // Complete only the minimizer's inverse view, after guarded determinization.
    let mut incoming: Vec<Vec<(usize, u16, u16)>> = vec![Vec::new(); dead + 1];
    for (source, state) in graph.states.iter().enumerate() {
        let mut cursor = 0_u32;
        for edge in &state.edges {
            let lo = u32::from(edge.lo);
            if cursor < lo {
                incoming[dead].push((source, cursor as u16, edge.lo - 1));
            }
            incoming[edge.to].push((source, edge.lo, edge.hi));
            cursor = u32::from(edge.hi) + 1;
        }
        if cursor < 65536 {
            incoming[dead].push((source, cursor as u16, u16::MAX));
        }
    }
    incoming[dead].push((dead, 0, u16::MAX));
    let mut blocks: Vec<BTreeSet<usize>> = Vec::new();
    for accepting in [false, true] {
        let members: BTreeSet<_> = (0..=dead)
            .filter(|&q| (q != dead && graph.states[q].accept) == accepting)
            .collect();
        if !members.is_empty() {
            blocks.push(members);
        }
    }
    let mut membership = vec![0; dead + 1];
    for (block, members) in blocks.iter().enumerate() {
        for &q in members {
            membership[q] = block;
        }
    }
    let mut pending = vec![true; blocks.len()];
    let mut queue: VecDeque<_> = (0..blocks.len()).collect();
    while let Some(splitter) = queue.pop_front() {
        pending[splitter] = false;
        // Snapshot the entire splitter before changing any membership, even if
        // the splitter splits itself during this batch.
        let mut signatures: BTreeMap<usize, Vec<(u16, u16)>> = BTreeMap::new();
        for &target in &blocks[splitter] {
            for &(source, lo, hi) in &incoming[target] {
                signatures.entry(source).or_default().push((lo, hi));
            }
        }
        let mut affected: BTreeMap<usize, BTreeMap<Vec<(u16, u16)>, Vec<usize>>> = BTreeMap::new();
        for (source, row) in signatures {
            affected
                .entry(membership[source])
                .or_default()
                .entry(intervals(row))
                .or_default()
                .push(source);
        }
        for (block, groups) in affected {
            let touched: usize = groups.values().map(Vec::len).sum();
            if groups.len() == 1 && touched == blocks[block].len() {
                continue;
            }
            let mut untouched = std::mem::take(&mut blocks[block]);
            let mut pieces: Vec<BTreeSet<usize>> = Vec::new();
            for sources in groups.into_values() {
                for source in &sources {
                    untouched.remove(source);
                }
                pieces.push(sources.into_iter().collect());
            }
            if !untouched.is_empty() {
                pieces.push(untouched);
            }
            let largest = pieces
                .iter()
                .enumerate()
                .max_by_key(|(_, piece)| piece.len())
                .unwrap()
                .0;
            // Stable block identity retains a largest piece. If it was pending,
            // its existing queue entry remains; otherwise it is the omitted half.
            blocks[block] = pieces.swap_remove(largest);
            for piece in pieces {
                let id = blocks.len();
                for &source in &piece {
                    membership[source] = id;
                }
                blocks.push(piece);
                pending.push(true);
                queue.push_back(id);
            }
        }
    }
    let mut states = Vec::with_capacity(blocks.len());
    for members in blocks {
        let representative = *members.first().unwrap();
        states.push(if representative == dead {
            State::default()
        } else {
            let source = &graph.states[representative];
            State {
                accept: source.accept,
                edges: source
                    .edges
                    .iter()
                    .map(|edge| Edge {
                        to: membership[edge.to],
                        ..*edge
                    })
                    .collect(),
            }
        });
    }
    graph.initial = membership[graph.initial];
    graph.states = states;
    graph.remove_dead();
}
