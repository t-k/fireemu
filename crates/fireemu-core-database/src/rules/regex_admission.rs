//! Load-time admission for the RTDB regular-expression dialect.
//! Canonical determinization failures are distinct from host and invariant failures.
//! Independently specified from tagged-automaton behavior; no upstream code is embedded.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
#[cfg(test)]
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

const PROTOTYPE_STATES: usize = 20_000;
const PROTOTYPE_EDGES: usize = 2_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Resource,
    Allocation,
    NonTerminatingCanonicalConstruction,
    Inconclusive,
    Integer,
    Syntax,
}

/// Checks every literal during parsing, including literals in unevaluated branches.
/// The shared matcher remains responsible for evaluation after successful admission.
pub(super) fn check(pattern: &str, ignore_case: bool) -> Result<(), &'static str> {
    let result = reader::literal(pattern, ignore_case)
        .and_then(|tree| tree.compile(5000, &mut ast::Trace::default()));
    result.map(|_| ()).map_err(failure_message)
}

fn failure_message(failure: Failure) -> &'static str {
    match failure {
        Failure::Resource => "Illegal regular expression, could not determinize efficiently",
        Failure::Allocation => "Could not check regular expression: allocation failed",
        Failure::NonTerminatingCanonicalConstruction => {
            "Could not check regular expression: case-insensitive range ends at U+FFFF"
        }
        // Successful reader-generated children are normalized; class complements and
        // products have at most three and six states respectively. Generic reference
        // helper limits are not an admission policy for valid reader-generated trees.
        Failure::Inconclusive => "Could not check regular expression: admission invariant failed",
        Failure::Integer | Failure::Syntax => {
            "Could not check regular expression: admission grammar disagrees with the literal parser"
        }
    }
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
#[cfg(test)]
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
    // Only literal expansion and certified clone may create this exact chain.
    word: Option<Arc<Vec<u16>>>,
    store: Option<persistent::Store>,
    states: Vec<State>,
    initial: usize,
    deterministic: bool,
}

enum Outgoing<'a> {
    Dense(std::iter::Copied<std::slice::Iter<'a, Edge>>),
    Word(std::option::IntoIter<Edge>),
    Persistent(persistent::Outgoing),
}
impl Iterator for Outgoing<'_> {
    type Item = Edge;
    fn next(&mut self) -> Option<Edge> {
        match self {
            Self::Dense(i) => i.next(),
            Self::Word(i) => i.next(),
            Self::Persistent(i) => i.next(),
        }
    }
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

#[cfg(test)]
thread_local! { static ALLOCATION_FAILURE_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) }; }

#[cfg_attr(
    not(test),
    allow(
        clippy::unnecessary_wraps,
        reason = "Test-only allocation faults use the same Result propagation as production."
    )
)]
fn allocation_point() -> Result<(), Failure> {
    #[cfg(test)]
    ALLOCATION_FAILURE_AFTER.with(|remaining| match remaining.get() {
        Some(0) => Err(Failure::Allocation),
        Some(n) => {
            remaining.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })?;
    Ok(())
}

#[cfg(test)]
struct AllocationFault;
#[cfg(test)]
impl AllocationFault {
    fn after(successful_reserves: usize) -> Self {
        ALLOCATION_FAILURE_AFTER.with(|n| n.set(Some(successful_reserves)));
        Self
    }
}
#[cfg(test)]
impl Drop for AllocationFault {
    fn drop(&mut self) {
        ALLOCATION_FAILURE_AFTER.with(|n| n.set(None));
    }
}

fn reserve_items<T>(items: &mut Vec<T>, additional: usize) -> Result<(), Failure> {
    allocation_point()?;
    items
        .try_reserve(additional)
        .map_err(|_| Failure::Allocation)
}

fn push_item<T>(items: &mut Vec<T>, item: T) -> Result<(), Failure> {
    reserve_items(items, 1)?;
    items.push(item);
    Ok(())
}

// Hashes index candidates only; exact sorted identity sets decide equality.
#[derive(Default)]
struct SubsetIndex {
    buckets: HashMap<u64, Vec<usize>>,
}
impl SubsetIndex {
    fn digest<K: Hash + ?Sized>(key: &K) -> u64 {
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hash);
        hash.finish()
    }
    fn find<K: Eq>(&self, digest: u64, key: &K, keys: &[K]) -> Option<usize> {
        self.buckets
            .get(&digest)?
            .iter()
            .copied()
            .find(|&id| &keys[id] == key)
    }
    fn insert(&mut self, digest: u64, id: usize) -> Result<(), Failure> {
        allocation_point()?;
        self.buckets
            .try_reserve(1)
            .map_err(|_| Failure::Allocation)?;
        let bucket = self.buckets.entry(digest).or_default();
        reserve_items(bucket, 1)?;
        bucket.push(id);
        Ok(())
    }
}

impl Graph {
    fn state_count(&self) -> usize {
        if let Some(store) = &self.store {
            return store.count();
        }
        self.word
            .as_ref()
            .map_or(self.states.len(), |word| word.len() + 1)
    }
    fn accepts(&self, q: usize) -> bool {
        if let Some(store) = &self.store {
            return store.accepts(q);
        }
        self.word
            .as_ref()
            .map_or_else(|| self.states[q].accept, |word| q == word.len())
    }
    fn outgoing(&self, q: usize) -> Outgoing<'_> {
        if let Some(store) = &self.store {
            return Outgoing::Persistent(store.outgoing(q));
        }
        if let Some(word) = &self.word {
            return Outgoing::Word(
                word.get(q)
                    .map(|&unit| Edge {
                        lo: unit,
                        hi: unit,
                        to: q + 1,
                    })
                    .into_iter(),
            );
        }
        Outgoing::Dense(self.states[q].edges.iter().copied())
    }
    fn ensure_store(&mut self) {
        if self.store.is_none() {
            self.store = Some(persistent::Store::from_graph(self));
            self.word = None;
            self.states.clear();
        }
    }
    fn set_accept(&mut self, q: usize, accept: bool) {
        self.ensure_store();
        self.store.as_mut().unwrap().set_accept(q, accept);
    }
    fn fresh(&mut self, accept: bool) -> Result<usize, Failure> {
        self.ensure_store();
        self.store.as_mut().unwrap().fresh(accept, Vec::new())
    }
    // Explicit constructor-only transition. Symbolic readers never call this.
    // Reader-generated constructors enter with normalized dense children, so
    // this generic reference-helper bound does not determine load admission.
    fn ensure_dense(&mut self) -> Result<(), Failure> {
        if let Some(store) = &self.store {
            state_bound(store.count())?;
            self.states = (0..store.count())
                .map(|q| State {
                    accept: store.accepts(q),
                    edges: store.outgoing(q).collect(),
                })
                .collect();
            self.store = None;
            return Ok(());
        }
        let Some(word) = &self.word else {
            return Ok(());
        };
        state_bound(word.len() + 1)?;
        #[cfg(test)]
        WORD_MATERIALIZATIONS.with(|count| count.set(count.get() + 1));
        self.states = (0..=word.len())
            .map(|q| State {
                accept: q == word.len(),
                edges: word
                    .get(q)
                    .map(|&unit| {
                        vec![Edge {
                            lo: unit,
                            hi: unit,
                            to: q + 1,
                        }]
                    })
                    .unwrap_or_default(),
            })
            .collect();
        self.word = None;
        Ok(())
    }
    fn empty() -> Self {
        Self {
            word: None,
            store: None,
            states: vec![State::default()],
            initial: 0,
            deterministic: true,
        }
    }

    fn reachable(&self) -> Vec<usize> {
        if self.word.is_some() {
            return (0..self.state_count()).collect();
        }
        let mut seen = BTreeSet::from([self.initial]);
        let mut queue = vec![self.initial];
        let mut cursor = 0;
        while cursor < queue.len() {
            for edge in self.outgoing(queue[cursor]) {
                if seen.insert(edge.to) {
                    queue.push(edge.to);
                }
            }
            cursor += 1;
        }
        queue
    }

    fn accepting(&self) -> Vec<usize> {
        if let Some(word) = &self.word {
            return vec![word.len()];
        }
        self.reachable()
            .into_iter()
            .filter(|&i| self.accepts(i))
            .collect()
    }

    // Import freezes the child's whole store version under a fresh namespace.
    // Legacy Dense append below remains separate for explicit reference paths.
    fn append_store(&mut self, other: &Self) -> Result<usize, Failure> {
        self.ensure_store();
        let child = persistent::Store::from_graph(other);
        let offset = self.store.as_mut().unwrap().import(&child)?;
        Ok(offset + other.initial)
    }

    #[cfg(test)]
    fn append(&mut self, other: &Self) -> Result<usize, Failure> {
        self.ensure_dense()?;
        let offset = self.states.len();
        state_bound(
            offset
                .checked_add(other.state_count())
                .ok_or(Failure::Inconclusive)?,
        )?;
        let edge_count = self
            .states
            .iter()
            .map(|state| state.edges.len())
            .sum::<usize>()
            + (0..other.state_count())
                .map(|q| other.outgoing(q).count())
                .sum::<usize>();
        if edge_count > PROTOTYPE_EDGES {
            return Err(Failure::Inconclusive);
        }
        self.states.extend((0..other.state_count()).map(|q| {
            State {
                accept: other.accepts(q),
                edges: other
                    .outgoing(q)
                    .map(|edge| Edge {
                        to: edge.to + offset,
                        ..edge
                    })
                    .collect(),
            }
        }));
        Ok(other.initial + offset)
    }

    // Copy the destination's outgoing edges now, without storing an epsilon edge.
    fn copy_edges(&mut self, from: usize, to: usize) -> Result<(), Failure> {
        if let Some(store) = &mut self.store {
            store.copy_edges(from, to);
            return Ok(());
        }
        self.ensure_dense()?;
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
        self.points_for(self.reachable())
    }

    fn points_for(&self, states: impl IntoIterator<Item = usize>) -> Vec<u16> {
        let mut points = BTreeSet::from([0]);
        for i in states {
            for e in self.outgoing(i) {
                points.insert(e.lo);
                if e.hi < u16::MAX {
                    points.insert(e.hi + 1);
                }
            }
        }
        points.into_iter().collect()
    }

    fn remove_dead(&mut self) {
        if self.word.is_some() {
            return;
        }
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
        let mut next_id = 0;
        for &i in &reachable {
            if live[i] {
                map[i] = next_id;
                next_id += 1;
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
        if let Some(word) = &self.word {
            // Each position and the empty successor are distinct reachable subsets.
            let count = word.len() as u64 + 2;
            guard_count(count, threshold)?;
            self.deterministic = true;
            return Ok(Some(count));
        }
        let initial = vec![self.initial];
        let mut subsets = vec![initial.clone()];
        let mut intern = SubsetIndex::default();
        intern.insert(SubsetIndex::digest(&initial), 0)?;
        let mut out = vec![State::default()];
        let mut cursor = 0usize;
        while cursor < subsets.len() {
            guard_count(cursor as u64 + 1, threshold)?;
            out[cursor].accept = subsets[cursor].iter().any(|&i| self.accepts(i));
            // Local endpoint atoms induce exactly the same successor subsets as
            // the jar's global atoms, without repeating unrelated endpoints.
            let mut events: BTreeMap<u32, Vec<(usize, bool)>> = BTreeMap::new();
            events.entry(0).or_default();
            events.entry(65536).or_default();
            for &i in &subsets[cursor] {
                for edge in self.outgoing(i) {
                    events
                        .entry(u32::from(edge.lo))
                        .or_default()
                        .push((edge.to, true));
                    events
                        .entry(u32::from(edge.hi) + 1)
                        .or_default()
                        .push((edge.to, false));
                }
            }
            let mut active: BTreeMap<usize, usize> = BTreeMap::new();
            let mut events = events.into_iter().peekable();
            while let Some((lo, changes)) = events.next() {
                let Some(&(end, _)) = events.peek() else {
                    break;
                };
                for (target, add) in changes {
                    if add {
                        *active.entry(target).or_default() += 1;
                    } else {
                        let count = active.get_mut(&target).unwrap();
                        *count -= 1;
                        if *count == 0 {
                            active.remove(&target);
                        }
                    }
                }
                let mut next = Vec::new();
                reserve_items(&mut next, active.len())?;
                next.extend(active.keys().copied());
                let digest = SubsetIndex::digest(&next);
                let to = if let Some(to) = intern.find(digest, &next, &subsets) {
                    to
                } else {
                    // Every discovered reachable subset must later be dequeued.
                    // Refuse its inevitable guarded dequeue before queue allocation.
                    guard_count(subsets.len() as u64 + 1, threshold)?;
                    reserve_items(&mut subsets, 1)?;
                    reserve_items(&mut out, 1)?;
                    let to = subsets.len();
                    intern.insert(digest, to)?;
                    subsets.push(next);
                    out.push(State::default());
                    to
                };
                let row = &mut out[cursor].edges;
                let hi =
                    u16::try_from(end - 1).expect("UTF-16 interval endpoint is at most U+FFFF");
                if let Some(last) = row.last_mut() {
                    if last.to == to && u32::from(last.hi) + 1 == lo {
                        last.hi = hi;
                        continue;
                    }
                }
                reserve_items(row, 1)?;
                row.push(Edge {
                    lo: u16::try_from(lo).expect("UTF-16 interval start is at most U+FFFF"),
                    hi,
                    to,
                });
            }
            cursor += 1;
        }
        *self = Self {
            word: None,
            store: None,
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
        minimize::refine(self);
        Ok(count)
    }

    #[cfg(test)]
    fn normal(&self) -> String {
        let mut ids = BTreeMap::from([(self.initial, 0)]);
        let mut queue = vec![self.initial];
        let mut out = String::from("G:");
        let mut cursor = 0;
        while cursor < queue.len() {
            let i = queue[cursor];
            write!(
                &mut out,
                "{}{}[",
                cursor,
                if self.accepts(i) { "+" } else { "-" }
            )
            .expect("writing to String cannot fail");
            let mut edges: Vec<_> = self.outgoing(i).collect();
            edges.sort_unstable_by_key(|e| (e.lo, e.hi, e.to));
            for e in edges {
                let next = ids.len();
                let id = *ids.entry(e.to).or_insert_with(|| {
                    queue.push(e.to);
                    next
                });
                write!(&mut out, "{}-{}:{},", e.lo, e.hi, id)
                    .expect("writing to String cannot fail");
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

    fn expanded(&self) -> Graph {
        match self {
            Self::Graph(g) => g.clone(),
            Self::Singleton(units) => Graph {
                word: Some(Arc::new(units.clone())),
                store: None,
                states: Vec::new(),
                initial: 0,
                deterministic: true,
            },
        }
    }

    fn concat(items: &[Self]) -> Result<Self, Failure> {
        if items.iter().all(|a| matches!(a, Self::Singleton(_))) {
            let length = items.iter().try_fold(0_usize, |length, item| {
                let Self::Singleton(part) = item else {
                    unreachable!()
                };
                length.checked_add(part.len()).ok_or(Failure::Allocation)
            })?;
            let mut units = Vec::new();
            reserve_word_units(&mut units, length)?;
            for item in items {
                let Self::Singleton(part) = item else {
                    unreachable!()
                };
                units.extend_from_slice(part);
            }
            return Ok(Self::Singleton(units));
        }
        let mut graphs = items.iter().map(Self::expanded).collect::<Vec<_>>();
        if graphs.iter().any(|g| g.accepting().is_empty()) {
            return Ok(Self::Graph(Graph::empty()));
        }
        if graphs.is_empty() {
            return Ok(Self::literal(""));
        }
        let mut result = graphs.remove(0);
        let mut accepting = result.accepting();
        for graph in graphs {
            if graph.accepts(graph.initial) && graph.outgoing(graph.initial).next().is_none() {
                continue;
            }
            let offset = result.state_count();
            let initial = result.append_store(&graph)?;
            let mut next: Vec<_> = graph.accepting().iter().map(|i| i + offset).collect();
            for i in accepting {
                result.set_accept(i, false);
                result.copy_edges(i, initial)?;
                if result.accepts(i) {
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
            let graph = item.expanded();
            if graph.accepting().is_empty() {
                continue;
            }
            let initial = result.append_store(&graph)?;
            result.copy_edges(0, initial)?;
        }
        result.deterministic = false;
        Ok(Self::Graph(result))
    }

    fn optional(&self) -> Result<Self, Failure> {
        let mut graph = self.expanded();
        let old = graph.initial;
        let initial = graph.fresh(false)?;
        graph.copy_edges(initial, old)?;
        graph.set_accept(initial, true);
        graph.initial = initial;
        graph.deterministic = false;
        Ok(Self::Graph(graph))
    }

    fn star(&self) -> Result<Self, Failure> {
        let mut graph = self.expanded();
        let accepting = graph.accepting();
        let old = graph.initial;
        let initial = graph.fresh(true)?;
        graph.copy_edges(initial, old)?;
        for i in accepting {
            graph.copy_edges(i, initial)?;
        }
        graph.initial = initial;
        graph.deterministic = false;
        Ok(Self::Graph(graph))
    }

    #[cfg(test)]
    fn bounded(&self, min: u32, max: u32) -> Result<Self, Failure> {
        if min > max {
            return Ok(Self::Graph(Graph::empty()));
        }
        let child = Self::Graph(self.expanded());
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
            let mut tail = child.expanded();
            for _ in 1..extra {
                let mut head = child.expanded();
                let accepting = head.accepting();
                let initial = head.append(&tail)?;
                for i in accepting {
                    head.copy_edges(i, initial)?;
                }
                tail = head;
            }
            let mut graph = result.expanded();
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
            word: None,
            store: None,
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

    #[cfg(test)]
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
        let mut graph = self.expanded();
        graph.determinize(threshold)?;
        graph.ensure_dense()?;
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
                let Some(edge) = graph.outgoing(state).find(|e| e.lo <= unit && unit <= e.hi)
                else {
                    return false;
                };
                state = edge.to;
            }
            graph.accepts(state)
        }
        if let Self::Singleton(word) = self {
            return Ok(if contains(&other.expanded(), word) {
                self.clone()
            } else {
                Self::Graph(Graph::empty())
            });
        }
        if matches!(other, Self::Singleton(_)) {
            return other.intersection(self);
        }
        let left = self.expanded();
        let right = other.expanded();
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
            states[cursor].accept = left.accepts(a) && right.accepts(b);
            for x in left.outgoing(a) {
                for y in right.outgoing(b) {
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
            word: None,
            store: None,
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

    #[cfg(test)]
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

#[cfg(test)]
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

#[path = "regex_admission/minimize.rs"]
mod minimize;

#[cfg(test)]
thread_local! { static WORD_MATERIALIZATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

// This is an actual host allocation/capacity result, never the canonical guard.
fn reserve_word_units(units: &mut Vec<u16>, additional: usize) -> Result<(), Failure> {
    units
        .try_reserve_exact(additional)
        .map_err(|_| Failure::Allocation)
}

#[path = "regex_admission/persistent.rs"]
mod persistent;
