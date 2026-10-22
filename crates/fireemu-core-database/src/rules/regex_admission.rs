//! Isolated admission-algebra prototype; deliberately not connected to the rules parser.
//! Prototype allocation bounds return Inconclusive and are never load-refusal policy.
//! Independently specified from tagged-automaton behavior; no upstream code is embedded.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

const PROTOTYPE_STATES: usize = 20_000;
const PROTOTYPE_EDGES: usize = 2_000_000;

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Resource,
    NonTerminatingCanonicalConstruction,
    Inconclusive,
    Integer,
    Syntax,
}

fn guard_count(count: u64, threshold: u64) -> Result<u64, Failure> {
    if count.saturating_sub(1) > threshold {
        Err(Failure::Resource)
    } else {
        Ok(count)
    }
}

// A forced-determinized finite chain also visits the empty successor subset.
// One exact copy remains a deterministic graph, and zero remains a singleton.
fn exact_literal_count(units: u64, copies: u64) -> Result<Option<u64>, Failure> {
    if copies <= 1 {
        return Ok(None);
    }
    units
        .checked_mul(copies)
        .and_then(|n| n.checked_add(2))
        .map(Some)
        .ok_or(Failure::Inconclusive)
}

fn jar_integer(text: &str) -> Result<u32, Failure> {
    let value = text.parse::<u32>().map_err(|_| Failure::Integer)?;
    if value > i32::MAX as u32 {
        Err(Failure::Integer)
    } else {
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    lo: u16,
    hi: u16,
    to: usize,
}

#[derive(Clone, Debug, Default)]
struct State {
    accept: bool,
    edges: Vec<Edge>,
}

#[derive(Clone, Debug)]
struct Graph {
    states: Vec<State>,
    initial: usize,
    deterministic: bool,
}

#[derive(Clone, Debug)]
enum Automaton {
    Singleton(Vec<u16>),
    Graph(Graph),
}

fn state_bound(count: usize) -> Result<(), Failure> {
    if count > PROTOTYPE_STATES {
        Err(Failure::Inconclusive)
    } else {
        Ok(())
    }
}

impl Graph {
    fn empty() -> Self {
        Self {
            states: vec![State::default()],
            initial: 0,
            deterministic: true,
        }
    }

    fn reachable(&self) -> Vec<usize> {
        let mut seen = vec![false; self.states.len()];
        let mut queue = vec![self.initial];
        seen[self.initial] = true;
        let mut cursor = 0;
        while cursor < queue.len() {
            for edge in &self.states[queue[cursor]].edges {
                if !seen[edge.to] {
                    seen[edge.to] = true;
                    queue.push(edge.to);
                }
            }
            cursor += 1;
        }
        queue
    }

    fn accepting(&self) -> Vec<usize> {
        self.reachable()
            .into_iter()
            .filter(|&i| self.states[i].accept)
            .collect()
    }

    fn append(&mut self, other: &Self) -> Result<usize, Failure> {
        let offset = self.states.len();
        state_bound(
            offset
                .checked_add(other.states.len())
                .ok_or(Failure::Inconclusive)?,
        )?;
        let edge_count = self
            .states
            .iter()
            .chain(&other.states)
            .map(|s| s.edges.len())
            .sum::<usize>();
        if edge_count > PROTOTYPE_EDGES {
            return Err(Failure::Inconclusive);
        }
        self.states.extend(other.states.iter().map(|s| {
            State {
                accept: s.accept,
                edges: s
                    .edges
                    .iter()
                    .map(|e| Edge {
                        to: e.to + offset,
                        ..*e
                    })
                    .collect(),
            }
        }));
        Ok(other.initial + offset)
    }

    // Copy the destination's outgoing edges now, without storing an epsilon edge.
    fn copy_edges(&mut self, from: usize, to: usize) -> Result<(), Failure> {
        let source = self.states[to].clone();
        if self.states[from].edges.len() + source.edges.len() > PROTOTYPE_EDGES {
            return Err(Failure::Inconclusive);
        }
        self.states[from].accept |= source.accept;
        self.states[from].edges.extend(source.edges);
        self.states[from].edges.sort_unstable();
        self.states[from].edges.dedup();
        Ok(())
    }

    fn points(&self) -> Vec<u16> {
        let mut points = BTreeSet::from([0]);
        for i in self.reachable() {
            for e in &self.states[i].edges {
                points.insert(e.lo);
                if e.hi < u16::MAX {
                    points.insert(e.hi + 1);
                }
            }
        }
        points.into_iter().collect()
    }

    fn remove_dead(&mut self) {
        let mut reverse = vec![Vec::new(); self.states.len()];
        for (i, state) in self.states.iter().enumerate() {
            for e in &state.edges {
                reverse[e.to].push(i);
            }
        }
        let mut live = vec![false; self.states.len()];
        let mut queue = VecDeque::new();
        for i in self.accepting() {
            live[i] = true;
            queue.push_back(i);
        }
        while let Some(i) = queue.pop_front() {
            for &pred in &reverse[i] {
                if !live[pred] {
                    live[pred] = true;
                    queue.push_back(pred);
                }
            }
        }
        if !live[self.initial] {
            *self = Self::empty();
            return;
        }
        let reachable = self.reachable();
        let mut map = vec![usize::MAX; self.states.len()];
        for &i in &reachable {
            if live[i] {
                map[i] = map.iter().filter(|&&n| n != usize::MAX).count();
            }
        }
        let mut states = Vec::new();
        for i in reachable {
            if live[i] {
                states.push(State {
                    accept: self.states[i].accept,
                    edges: self.states[i]
                        .edges
                        .iter()
                        .filter(|e| live[e.to])
                        .map(|e| Edge {
                            to: map[e.to],
                            ..*e
                        })
                        .collect(),
                });
            }
        }
        self.initial = map[self.initial];
        self.states = states;
        self.reduce_edges();
    }

    fn reduce_edges(&mut self) {
        for state in &mut self.states {
            state.edges.sort_unstable_by_key(|e| (e.to, e.lo, e.hi));
            let mut merged: Vec<Edge> = Vec::new();
            for &edge in &state.edges {
                if let Some(last) = merged.last_mut() {
                    if last.to == edge.to && u32::from(edge.lo) <= u32::from(last.hi) + 1 {
                        last.hi = last.hi.max(edge.hi);
                        continue;
                    }
                }
                merged.push(edge);
            }
            merged.sort_unstable_by_key(|e| (e.lo, e.hi, e.to));
            state.edges = merged;
        }
    }

    fn determinize(&mut self, threshold: u64) -> Result<Option<u64>, Failure> {
        if self.deterministic {
            return Ok(None);
        }
        let points = self.points();
        let initial = vec![self.initial];
        let mut subsets = vec![initial.clone()];
        let mut intern = BTreeMap::from([(initial, 0)]);
        let mut out = vec![State::default()];
        let mut cursor = 0usize;
        let mut edges = 0usize;
        let mut subset_units = 1usize;
        while cursor < subsets.len() {
            guard_count(cursor as u64 + 1, threshold)?;
            let current = subsets[cursor].clone();
            out[cursor].accept = current.iter().any(|&i| self.states[i].accept);
            for (n, &lo) in points.iter().enumerate() {
                let mut next = BTreeSet::new();
                for &i in &current {
                    for e in &self.states[i].edges {
                        if e.lo <= lo && lo <= e.hi {
                            next.insert(e.to);
                        }
                    }
                }
                let next: Vec<_> = next.into_iter().collect();
                let to = if let Some(&to) = intern.get(&next) {
                    to
                } else {
                    state_bound(subsets.len() + 1)?;
                    subset_units += next.len();
                    if subset_units > PROTOTYPE_EDGES {
                        return Err(Failure::Inconclusive);
                    }
                    let to = subsets.len();
                    intern.insert(next.clone(), to);
                    subsets.push(next);
                    out.push(State::default());
                    to
                };
                // The actual jar interns even the empty successor subset.
                let hi = points.get(n + 1).map_or(u16::MAX, |&p| p - 1);
                out[cursor].edges.push(Edge { lo, hi, to });
                edges += 1;
                if edges > PROTOTYPE_EDGES {
                    return Err(Failure::Inconclusive);
                }
            }
            cursor += 1;
        }
        *self = Self {
            states: out,
            initial: 0,
            deterministic: true,
        };
        self.remove_dead();
        Ok(Some(cursor as u64))
    }

    fn minimize(&mut self, threshold: u64) -> Result<Option<u64>, Failure> {
        let count = self.determinize(threshold)?;
        self.remove_dead();
        let points = self.points();
        let mut classes: Vec<usize> = self.states.iter().map(|s| usize::from(s.accept)).collect();
        let mut work = 0usize;
        loop {
            let mut intern = BTreeMap::new();
            let mut next = Vec::with_capacity(self.states.len());
            for state in &self.states {
                let mut signature = vec![usize::from(state.accept)];
                for &point in &points {
                    let target = state
                        .edges
                        .iter()
                        .find(|e| e.lo <= point && point <= e.hi)
                        .map_or(usize::MAX, |e| classes[e.to]);
                    signature.push(target);
                    work += 1;
                    if work > PROTOTYPE_EDGES {
                        return Err(Failure::Inconclusive);
                    }
                }
                let next_id = intern.len();
                let class = *intern.entry(signature).or_insert(next_id);
                next.push(class);
            }
            if next == classes {
                break;
            }
            classes = next;
        }
        let class_count = classes.iter().max().copied().unwrap_or(0) + 1;
        let mut states = vec![State::default(); class_count];
        let mut filled = vec![false; class_count];
        for (i, state) in self.states.iter().enumerate() {
            let class = classes[i];
            if !filled[class] {
                states[class] = State {
                    accept: state.accept,
                    edges: state
                        .edges
                        .iter()
                        .map(|e| Edge {
                            to: classes[e.to],
                            ..*e
                        })
                        .collect(),
                };
                filled[class] = true;
            }
        }
        self.initial = classes[self.initial];
        self.states = states;
        self.reduce_edges();
        Ok(count)
    }

    fn normal(&self) -> String {
        let mut ids = BTreeMap::from([(self.initial, 0)]);
        let mut queue = vec![self.initial];
        let mut out = String::from("G:");
        let mut cursor = 0;
        while cursor < queue.len() {
            let i = queue[cursor];
            let state = &self.states[i];
            out.push_str(&format!(
                "{}{}[",
                cursor,
                if state.accept { "+" } else { "-" }
            ));
            let mut edges = state.edges.clone();
            edges.sort_unstable_by_key(|e| (e.lo, e.hi, e.to));
            for e in edges {
                let next = ids.len();
                let id = *ids.entry(e.to).or_insert_with(|| {
                    queue.push(e.to);
                    next
                });
                out.push_str(&format!("{}-{}:{},", e.lo, e.hi, id));
            }
            out.push(']');
            cursor += 1;
        }
        out
    }
}

impl Automaton {
    fn literal(text: &str) -> Self {
        Self::Singleton(text.encode_utf16().collect())
    }

    fn expanded(&self) -> Result<Graph, Failure> {
        match self {
            Self::Graph(g) => Ok(g.clone()),
            Self::Singleton(units) => {
                state_bound(units.len().checked_add(1).ok_or(Failure::Inconclusive)?)?;
                let mut states = vec![State::default(); units.len() + 1];
                for (i, &unit) in units.iter().enumerate() {
                    states[i].edges.push(Edge {
                        lo: unit,
                        hi: unit,
                        to: i + 1,
                    });
                }
                states[units.len()].accept = true;
                Ok(Graph {
                    states,
                    initial: 0,
                    deterministic: true,
                })
            }
        }
    }

    fn concat(items: &[Self]) -> Result<Self, Failure> {
        if items.iter().all(|a| matches!(a, Self::Singleton(_))) {
            let mut units = Vec::new();
            for item in items {
                let Self::Singleton(part) = item else {
                    unreachable!()
                };
                state_bound(
                    units
                        .len()
                        .checked_add(part.len())
                        .ok_or(Failure::Inconclusive)?,
                )?;
                units.extend(part);
            }
            return Ok(Self::Singleton(units));
        }
        let mut graphs = items
            .iter()
            .map(Self::expanded)
            .collect::<Result<Vec<_>, _>>()?;
        if graphs.iter().any(|g| g.accepting().is_empty()) {
            return Ok(Self::Graph(Graph::empty()));
        }
        if graphs.is_empty() {
            return Ok(Self::literal(""));
        }
        let mut result = graphs.remove(0);
        let mut accepting = result.accepting();
        for graph in graphs {
            if graph.states[graph.initial].accept && graph.states[graph.initial].edges.is_empty() {
                continue;
            }
            let offset = result.states.len();
            let initial = result.append(&graph)?;
            let mut next: Vec<_> = graph.accepting().iter().map(|i| i + offset).collect();
            for i in accepting {
                result.states[i].accept = false;
                result.copy_edges(i, initial)?;
                if result.states[i].accept {
                    next.push(i);
                }
            }
            accepting = next;
        }
        result.deterministic = false;
        Ok(Self::Graph(result))
    }

    fn collection_union(items: &[Self]) -> Result<Self, Failure> {
        let mut result = Graph::empty();
        for item in items {
            let graph = item.expanded()?;
            if graph.accepting().is_empty() {
                continue;
            }
            let initial = result.append(&graph)?;
            result.copy_edges(0, initial)?;
        }
        result.deterministic = false;
        Ok(Self::Graph(result))
    }

    fn optional(&self) -> Result<Self, Failure> {
        let mut graph = self.expanded()?;
        state_bound(graph.states.len() + 1)?;
        let old = graph.initial;
        let initial = graph.states.len();
        graph.states.push(State::default());
        graph.copy_edges(initial, old)?;
        graph.states[initial].accept = true;
        graph.initial = initial;
        graph.deterministic = false;
        Ok(Self::Graph(graph))
    }

    fn star(&self) -> Result<Self, Failure> {
        let mut graph = self.expanded()?;
        state_bound(graph.states.len() + 1)?;
        let accepting = graph.accepting();
        let old = graph.initial;
        let initial = graph.states.len();
        graph.states.push(State {
            accept: true,
            edges: Vec::new(),
        });
        graph.copy_edges(initial, old)?;
        for i in accepting {
            graph.copy_edges(i, initial)?;
        }
        graph.initial = initial;
        graph.deterministic = false;
        Ok(Self::Graph(graph))
    }

    fn bounded(&self, min: u32, max: u32) -> Result<Self, Failure> {
        if min > max {
            return Ok(Self::Graph(Graph::empty()));
        }
        let child = Self::Graph(self.expanded()?);
        if max as usize > PROTOTYPE_STATES {
            return Err(Failure::Inconclusive);
        }
        let mut result = match min {
            0 => Self::literal(""),
            1 => child.clone(),
            _ => Self::concat(&vec![child.clone(); min as usize])?,
        };
        let extra = max - min;
        if extra > 0 {
            let mut tail = child.expanded()?;
            for _ in 1..extra {
                let mut head = child.expanded()?;
                let accepting = head.accepting();
                let initial = head.append(&tail)?;
                for i in accepting {
                    head.copy_edges(i, initial)?;
                }
                tail = head;
            }
            let mut graph = result.expanded()?;
            let accepting = graph.accepting();
            let initial = graph.append(&tail)?;
            for i in accepting {
                graph.copy_edges(i, initial)?;
            }
            graph.deterministic = false;
            result = Self::Graph(graph);
        }
        Ok(result)
    }

    fn range(lo: u16, hi: u16) -> Self {
        if lo > hi {
            return Self::Graph(Graph::empty());
        }
        if lo == hi {
            return Self::Singleton(vec![lo]);
        }
        Self::Graph(Graph {
            initial: 0,
            deterministic: true,
            states: vec![
                State {
                    accept: false,
                    edges: vec![Edge { lo, hi, to: 1 }],
                },
                State {
                    accept: true,
                    edges: Vec::new(),
                },
            ],
        })
    }

    fn minimum(&self, min: u32) -> Result<Self, Failure> {
        if min == 0 {
            return self.star();
        }
        if min as usize > PROTOTYPE_STATES {
            return Err(Failure::Inconclusive);
        }
        let mut items = vec![self.clone(); min as usize];
        // The star tail is intentionally not minimized before list concatenation.
        items.push(self.star()?);
        Self::concat(&items)
    }

    fn complement(&self, threshold: u64) -> Result<Self, Failure> {
        let mut graph = self.expanded()?;
        graph.determinize(threshold)?;
        let points = graph.points();
        let old_len = graph.states.len();
        let mut gaps = Vec::new();
        for i in 0..old_len {
            for (n, &lo) in points.iter().enumerate() {
                if !graph.states[i]
                    .edges
                    .iter()
                    .any(|e| e.lo <= lo && lo <= e.hi)
                {
                    gaps.push((i, lo, points.get(n + 1).map_or(u16::MAX, |&p| p - 1)));
                    if gaps.len() > PROTOTYPE_EDGES {
                        return Err(Failure::Inconclusive);
                    }
                }
            }
        }
        if !gaps.is_empty() {
            state_bound(old_len + 1)?;
            graph.states.push(State {
                accept: false,
                edges: vec![Edge {
                    lo: 0,
                    hi: u16::MAX,
                    to: old_len,
                }],
            });
            for (i, lo, hi) in gaps {
                graph.states[i].edges.push(Edge {
                    lo,
                    hi,
                    to: old_len,
                });
            }
        }
        for state in &mut graph.states {
            state.accept = !state.accept;
        }
        graph.remove_dead();
        Ok(Self::Graph(graph))
    }

    fn intersection(&self, other: &Self) -> Result<Self, Failure> {
        fn contains(graph: &Graph, word: &[u16]) -> bool {
            let mut state = graph.initial;
            for &unit in word {
                let Some(edge) = graph.states[state]
                    .edges
                    .iter()
                    .find(|e| e.lo <= unit && unit <= e.hi)
                else {
                    return false;
                };
                state = edge.to;
            }
            graph.states[state].accept
        }
        if let Self::Singleton(word) = self {
            return Ok(if contains(&other.expanded()?, word) {
                self.clone()
            } else {
                Self::Graph(Graph::empty())
            });
        }
        if matches!(other, Self::Singleton(_)) {
            return other.intersection(self);
        }
        let left = self.expanded()?;
        let right = other.expanded()?;
        if !left.deterministic || !right.deterministic {
            return Err(Failure::Inconclusive);
        }
        let initial = (left.initial, right.initial);
        let mut pairs = vec![initial];
        let mut intern = BTreeMap::from([(initial, 0)]);
        let mut states = vec![State::default()];
        let mut cursor = 0;
        while cursor < pairs.len() {
            let (a, b) = pairs[cursor];
            states[cursor].accept = left.states[a].accept && right.states[b].accept;
            for x in &left.states[a].edges {
                for y in &right.states[b].edges {
                    let lo = x.lo.max(y.lo);
                    let hi = x.hi.min(y.hi);
                    if lo > hi {
                        continue;
                    }
                    let pair = (x.to, y.to);
                    let to = if let Some(&to) = intern.get(&pair) {
                        to
                    } else {
                        state_bound(pairs.len() + 1)?;
                        let to = pairs.len();
                        pairs.push(pair);
                        intern.insert(pair, to);
                        states.push(State::default());
                        to
                    };
                    states[cursor].edges.push(Edge { lo, hi, to });
                }
            }
            cursor += 1;
        }
        let mut graph = Graph {
            states,
            initial: 0,
            deterministic: true,
        };
        graph.remove_dead();
        Ok(Self::Graph(graph))
    }

    fn minimize(&mut self, threshold: u64) -> Result<Option<u64>, Failure> {
        match self {
            Self::Singleton(_) => Ok(None),
            Self::Graph(graph) => graph.minimize(threshold),
        }
    }

    fn normal(&self) -> String {
        match self {
            Self::Singleton(units) => format!(
                "S:{}",
                units
                    .iter()
                    .map(|c| format!("{c:04x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::Graph(graph) => graph.normal(),
        }
    }
}

fn trace_case(name: &str) -> Result<String, Failure> {
    let a = Automaton::literal("a");
    let mut value = match name {
        "literal" => a,
        "concat-singleton" => Automaton::concat(&[a, Automaton::literal("b")])?,
        "exact-one" => a.bounded(1, 1)?,
        "exact-two" => a.bounded(2, 2)?,
        "exact-empty-two" => Automaton::literal("").bounded(2, 2)?,
        "union-duplicate" => Automaton::collection_union(&[a.clone(), a])?,
        "optional" => a.optional()?,
        "star-empty" => Automaton::literal("").star()?,
        "star-a" => a.star()?,
        "bounded-zero-two" => a.bounded(0, 2)?,
        "concat-graph-singleton" => {
            Automaton::concat(&[a.bounded(1, 1)?, Automaton::literal("b")])?
        }
        _ => return Err(Failure::Inconclusive),
    };
    let (tag, deterministic) = match &value {
        Automaton::Singleton(_) => ("S", true),
        Automaton::Graph(graph) => ("G", graph.deterministic),
    };
    let count = value
        .minimize(5000)?
        .map_or("skip".to_owned(), |n| n.to_string());
    Ok(format!(
        "{tag}\t{deterministic}\t{count}\t{}",
        value.normal()
    ))
}

#[path = "regex_admission/reader.rs"]
mod reader;

#[path = "regex_admission/ast.rs"]
mod ast;

#[path = "regex_admission/minimum.rs"]
mod minimum;

#[path = "regex_admission/symbolic.rs"]
mod symbolic;

#[cfg(test)]
#[path = "regex_admission/tests.rs"]
mod tests;

#[path = "regex_admission/java21_case.rs"]
mod java21_case;
