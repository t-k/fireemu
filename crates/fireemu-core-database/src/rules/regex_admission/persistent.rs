//! Persistent constructor primitives; Graph routing remains separate.
use super::{Edge, Failure, Graph, State};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type RowHandle = Arc<Row>;

enum Row {
    Empty,
    Edges(Arc<Vec<Edge>>),
    Dense(Arc<Vec<State>>, usize),
    Word(Arc<Vec<u16>>, usize),
    Union(RowHandle, RowHandle),
    Shift(RowHandle, usize),
}

// A row freezes edge triples, never the current state of their destinations.
impl Drop for Row {
    fn drop(&mut self) {
        fn detach(row: &mut Row, pending: &mut Vec<RowHandle>) {
            match row {
                Row::Union(a, b) => {
                    pending.push(std::mem::replace(a, Arc::new(Row::Empty)));
                    pending.push(std::mem::replace(b, Arc::new(Row::Empty)));
                }
                Row::Shift(a, _) => {
                    pending.push(std::mem::replace(a, Arc::new(Row::Empty)));
                }
                _ => {}
            }
        }
        let mut pending = Vec::new();
        detach(self, &mut pending);
        while let Some(handle) = pending.pop() {
            if let Ok(mut row) = Arc::try_unwrap(handle) {
                detach(&mut row, &mut pending);
            }
        }
    }
}

#[derive(Clone, Default)]
struct Override {
    accept: Option<bool>,
    row: Option<RowHandle>,
}

#[derive(Clone)]
struct Component {
    start: usize,
    count: usize,
    snapshot: Arc<Snapshot>,
}

#[derive(Clone)]
struct Recipe {
    count: usize,
    components: Vec<Component>,
    overrides: BTreeMap<usize, Override>,
}

impl Recipe {
    fn component(&self, q: usize) -> &Component {
        let i = self
            .components
            .partition_point(|component| component.start <= q);
        let component = &self.components[i - 1];
        assert!(q - component.start < component.count);
        component
    }
}

#[derive(Clone)]
enum Snapshot {
    Word(Arc<Vec<u16>>),
    Dense(Arc<Vec<State>>),
    Recipe(Recipe),
}

impl Snapshot {
    fn count(&self) -> usize {
        match self {
            Self::Word(word) => word.len() + 1,
            Self::Dense(states) => states.len(),
            Self::Recipe(recipe) => recipe.count,
        }
    }
}

// Import chains are temporal DAGs too; releasing them must not recurse.
impl Drop for Snapshot {
    fn drop(&mut self) {
        fn detach(snapshot: &mut Snapshot, pending: &mut Vec<Arc<Snapshot>>) {
            if let Snapshot::Recipe(recipe) = snapshot {
                pending.extend(
                    std::mem::take(&mut recipe.components)
                        .into_iter()
                        .map(|component| component.snapshot),
                );
            }
        }
        let mut pending = Vec::new();
        detach(self, &mut pending);
        while let Some(handle) = pending.pop() {
            if let Ok(mut snapshot) = Arc::try_unwrap(handle) {
                detach(&mut snapshot, &mut pending);
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Store {
    snapshot: Arc<Snapshot>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("count", &self.count())
            .finish_non_exhaustive()
    }
}

impl Store {
    pub(super) fn from_graph(graph: &Graph) -> Self {
        if let Some(store) = &graph.store {
            return store.clone();
        }
        Self {
            snapshot: Arc::new(if let Some(word) = &graph.word {
                Snapshot::Word(word.clone())
            } else {
                Snapshot::Dense(Arc::new(graph.states.clone()))
            }),
        }
    }

    pub(super) fn count(&self) -> usize {
        self.snapshot.count()
    }

    // Shared retained versions cause Arc::make_mut to clone the recipe's component
    // vector and override map. Repeated retained updates can therefore be quadratic;
    // immutable row sharing does not imply constant-time recipe updates.
    fn recipe(&mut self) -> &mut Recipe {
        if !matches!(self.snapshot.as_ref(), Snapshot::Recipe(_)) {
            let snapshot = self.snapshot.clone();
            let count = snapshot.count();
            self.snapshot = Arc::new(Snapshot::Recipe(Recipe {
                count,
                components: vec![Component {
                    start: 0,
                    count,
                    snapshot,
                }],
                overrides: BTreeMap::new(),
            }));
        }
        let Snapshot::Recipe(recipe) = Arc::make_mut(&mut self.snapshot) else {
            unreachable!()
        };
        recipe
    }

    pub(super) fn accepts(&self, mut q: usize) -> bool {
        assert!(q < self.count());
        let mut snapshot = self.snapshot.clone();
        loop {
            let next = match snapshot.as_ref() {
                Snapshot::Word(word) => return q == word.len(),
                Snapshot::Dense(states) => return states[q].accept,
                Snapshot::Recipe(recipe) => {
                    if let Some(accept) = recipe.overrides.get(&q).and_then(|value| value.accept) {
                        return accept;
                    }
                    let component = recipe.component(q);
                    q -= component.start;
                    component.snapshot.clone()
                }
            };
            snapshot = next;
        }
    }

    fn row(&self, mut q: usize) -> RowHandle {
        assert!(q < self.count());
        let mut snapshot = self.snapshot.clone();
        let mut offset = 0;
        loop {
            let next = match snapshot.as_ref() {
                Snapshot::Word(word) => {
                    let row = Arc::new(Row::Word(word.clone(), q));
                    return if offset == 0 {
                        row
                    } else {
                        Arc::new(Row::Shift(row, offset))
                    };
                }
                Snapshot::Dense(states) => {
                    let row = Arc::new(Row::Dense(states.clone(), q));
                    return if offset == 0 {
                        row
                    } else {
                        Arc::new(Row::Shift(row, offset))
                    };
                }
                Snapshot::Recipe(recipe) => {
                    if let Some(row) = recipe
                        .overrides
                        .get(&q)
                        .and_then(|value| value.row.as_ref())
                    {
                        return if offset == 0 {
                            row.clone()
                        } else {
                            Arc::new(Row::Shift(row.clone(), offset))
                        };
                    }
                    let component = recipe.component(q);
                    q -= component.start;
                    // Each import checked its complete range before installation.
                    offset += component.start;
                    component.snapshot.clone()
                }
            };
            snapshot = next;
        }
    }

    pub(super) fn outgoing(&self, q: usize) -> Outgoing {
        Outgoing {
            pending: vec![Frame::Node(self.row(q), 0)],
            seen: BTreeSet::new(),
            emitted: BTreeSet::new(),
        }
    }

    pub(super) fn set_accept(&mut self, q: usize, accept: bool) {
        assert!(q < self.count());
        self.recipe().overrides.entry(q).or_default().accept = Some(accept);
    }

    #[cfg(test)]
    pub(super) fn set_edges(&mut self, q: usize, edges: Vec<Edge>) {
        assert!(q < self.count());
        assert!(edges.iter().all(|edge| edge.to < self.count()));
        self.recipe().overrides.entry(q).or_default().row =
            Some(Arc::new(Row::Edges(Arc::new(edges))));
    }

    pub(super) fn fresh(&mut self, accept: bool, edges: Vec<Edge>) -> Result<usize, Failure> {
        let q = self.count();
        let count = q.checked_add(1).ok_or(Failure::Allocation)?;
        assert!(edges.iter().all(|edge| edge.to < count));
        let row = Arc::new(Row::Edges(Arc::new(edges)));
        let recipe = self.recipe();
        recipe.count = count;
        recipe.overrides.insert(
            q,
            Override {
                accept: Some(accept),
                row: Some(row),
            },
        );
        Ok(q)
    }

    pub(super) fn copy_edges(&mut self, from: usize, to: usize) {
        if from == to {
            return;
        }
        let accept = self.accepts(from) || self.accepts(to);
        let a = self.row(from);
        let b = self.row(to);
        let row = if Arc::ptr_eq(&a, &b) {
            a
        } else {
            Arc::new(Row::Union(a, b))
        };
        let value = self.recipe().overrides.entry(from).or_default();
        value.accept = Some(accept);
        value.row = Some(row);
    }

    pub(super) fn import(&mut self, other: &Self) -> Result<usize, Failure> {
        let start = self.count();
        let count = other.count();
        let total = start.checked_add(count).ok_or(Failure::Allocation)?;
        let snapshot = other.snapshot.clone();
        let recipe = self.recipe();
        recipe.components.push(Component {
            start,
            count,
            snapshot,
        });
        recipe.count = total;
        Ok(start)
    }
}

enum Frame {
    Node(RowHandle, usize),
    Edges(Arc<Vec<Edge>>, usize, usize),
    Dense(Arc<Vec<State>>, usize, usize, usize),
}

pub(super) struct Outgoing {
    pending: Vec<Frame>,
    // The same row under two namespace mappings has different destinations.
    seen: BTreeSet<(usize, usize)>,
    emitted: BTreeSet<Edge>,
}

impl Iterator for Outgoing {
    type Item = Edge;
    fn next(&mut self) -> Option<Edge> {
        while let Some(frame) = self.pending.pop() {
            let edge = match frame {
                Frame::Node(row, offset) => {
                    if !self.seen.insert((Arc::as_ptr(&row) as usize, offset)) {
                        continue;
                    }
                    match row.as_ref() {
                        Row::Empty => {}
                        Row::Edges(edges) => {
                            self.pending.push(Frame::Edges(edges.clone(), 0, offset));
                        }
                        Row::Dense(states, q) => {
                            self.pending
                                .push(Frame::Dense(states.clone(), *q, 0, offset));
                        }
                        Row::Word(word, q) => {
                            if let Some(&unit) = word.get(*q) {
                                let edge = Edge {
                                    lo: unit,
                                    hi: unit,
                                    to: q + 1 + offset,
                                };
                                if self.emitted.insert(edge) {
                                    return Some(edge);
                                }
                            }
                        }
                        Row::Union(a, b) => {
                            self.pending.push(Frame::Node(b.clone(), offset));
                            self.pending.push(Frame::Node(a.clone(), offset));
                        }
                        Row::Shift(row, shift) => {
                            self.pending.push(Frame::Node(row.clone(), offset + shift));
                        }
                    }
                    continue;
                }
                Frame::Edges(edges, index, offset) => {
                    let Some(&edge) = edges.get(index) else {
                        continue;
                    };
                    self.pending.push(Frame::Edges(edges, index + 1, offset));
                    Edge {
                        to: edge.to + offset,
                        ..edge
                    }
                }
                Frame::Dense(states, q, index, offset) => {
                    let Some(&edge) = states[q].edges.get(index) else {
                        continue;
                    };
                    self.pending
                        .push(Frame::Dense(states, q, index + 1, offset));
                    Edge {
                        to: edge.to + offset,
                        ..edge
                    }
                }
            };
            if self.emitted.insert(edge) {
                return Some(edge);
            }
        }
        None
    }
}
