//! Canonical-tree compiler for load-time regular-expression admission.
use super::{Automaton, Failure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Ast {
    Empty,
    Any,
    Literal(u16),
    String(Vec<u16>),
    Range(u16, u16),
    Union(Box<Self>, Box<Self>),
    Concat(Box<Self>, Box<Self>),
    Intersection(Box<Self>, Box<Self>),
    Complement(Box<Self>),
    Optional(Box<Self>),
    Star(Box<Self>),
    Minimum(u32, Box<Self>),
    Bounded(u32, u32, Box<Self>),
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct Step {
    pub node: &'static str,
    pub singleton: bool,
    pub deterministic: bool,
    pub guard: Option<u64>,
}

#[cfg(test)]
pub(super) type Trace = Vec<Step>;
#[cfg(not(test))]
pub(super) type Trace = ();

fn record_step(
    trace: &mut Trace,
    node: &'static str,
    singleton: bool,
    deterministic: bool,
    guard: Option<u64>,
) {
    #[cfg(test)]
    trace.push(Step {
        node,
        singleton,
        deterministic,
        guard,
    });
    #[cfg(not(test))]
    let _ = (trace, node, singleton, deterministic, guard);
}

impl Ast {
    pub(super) fn ascii_char(unit: u16) -> Self {
        if super::java21_case::alphabetic(unit) {
            Self::Union(
                Box::new(Self::Literal(super::java21_case::lower(unit))),
                Box::new(Self::Literal(super::java21_case::upper(unit))),
            )
        } else {
            Self::Literal(unit)
        }
    }

    pub(super) fn ascii_range(lo: u16, hi: u16) -> Result<Self, Failure> {
        // RegExp2's char loop wraps at FFFF and cannot return from this constructor.
        // This is a distinct engineering refusal, not the 5000-state guard.
        if hi == u16::MAX {
            return Err(Failure::NonTerminatingCanonicalConstruction);
        }
        let mut result = Self::Empty;
        let mut alphabetic = super::java21_case::alphabetic(lo);
        for unit in lo..=hi {
            let next = super::java21_case::alphabetic(unit);
            if next != alphabetic || unit == hi {
                let end = if unit == hi { unit } else { unit - 1 };
                let part = if alphabetic {
                    Self::Union(
                        Box::new(Self::Range(
                            super::java21_case::lower(lo),
                            super::java21_case::lower(end),
                        )),
                        Box::new(Self::Range(
                            super::java21_case::upper(lo),
                            super::java21_case::upper(end),
                        )),
                    )
                } else {
                    Self::Range(lo, end)
                };
                // Actual RegExp2 retains the original lo across category partitions.
                result = Self::Union(Box::new(result), Box::new(part));
                alphabetic = next;
            }
        }
        Ok(result)
    }

    fn leaves(&self, union: bool) -> Vec<&Self> {
        let mut pending = vec![self];
        let mut result = Vec::new();
        while let Some(node) = pending.pop() {
            match node {
                Self::Union(a, b) if union => {
                    pending.push(b);
                    pending.push(a);
                }
                Self::Concat(a, b) if !union => {
                    pending.push(b);
                    pending.push(a);
                }
                _ => result.push(node),
            }
        }
        result
    }

    pub(super) fn compile(&self, threshold: u64, trace: &mut Trace) -> Result<Automaton, Failure> {
        enum Task<'a> {
            Visit(&'a Ast),
            Apply(&'a Ast, usize),
        }
        let mut tasks = vec![Task::Visit(self)];
        let mut values = Vec::new();
        while let Some(task) = tasks.pop() {
            let (node, count) = match task {
                Task::Visit(node) => {
                    let children = match node {
                        Self::Union(..) => node.leaves(true),
                        Self::Concat(..) => node.leaves(false),
                        Self::Intersection(a, b) => vec![a.as_ref(), b.as_ref()],
                        Self::Complement(a)
                        | Self::Optional(a)
                        | Self::Star(a)
                        | Self::Minimum(_, a)
                        | Self::Bounded(_, _, a) => vec![a.as_ref()],
                        _ => Vec::new(),
                    };
                    tasks.push(Task::Apply(node, children.len()));
                    tasks.extend(children.into_iter().rev().map(Task::Visit));
                    continue;
                }
                Task::Apply(node, count) => (node, count),
            };
            let mut children = values.split_off(values.len() - count);
            let (mut value, label) = match node {
                Self::Empty => (Automaton::Graph(super::Graph::empty()), "empty"),
                Self::Any => (Automaton::range(0, u16::MAX), "any"),
                Self::Literal(c) => (Automaton::Singleton(vec![*c]), "literal"),
                Self::String(s) => (Automaton::Singleton(s.clone()), "string"),
                Self::Range(lo, hi) => (Automaton::range(*lo, *hi), "range"),
                Self::Union(..) => (Automaton::collection_union(&children)?, "union"),
                Self::Concat(..) => (Automaton::concat(&children)?, "concat"),
                Self::Intersection(..) => (children[0].intersection(&children[1])?, "intersection"),
                Self::Complement(..) => {
                    (children.pop().unwrap().complement(threshold)?, "complement")
                }
                Self::Optional(..) => (children.pop().unwrap().optional()?, "optional"),
                Self::Star(..) => (children.pop().unwrap().star()?, "star"),
                Self::Minimum(min, _) => {
                    let child = children.pop().unwrap().expanded();
                    let (value, count) = super::minimum::compile(&child, *min, threshold)?;
                    record_step(trace, "minimum", false, count.is_none(), count);
                    values.push(value);
                    continue;
                }
                Self::Bounded(min, max, _) => {
                    let child = children.pop().unwrap().expanded();
                    let (value, count) = super::symbolic::bounded(&child, *min, *max, threshold)?;
                    record_step(
                        trace,
                        "bounded",
                        matches!(value, Automaton::Singleton(_)),
                        count.is_none(),
                        count,
                    );
                    values.push(value);
                    continue;
                }
            };
            let (singleton, deterministic) = match &value {
                Automaton::Singleton(_) => (true, true),
                Automaton::Graph(graph) => (false, graph.deterministic),
            };
            let guard = value.minimize(threshold)?;
            record_step(trace, label, singleton, deterministic, guard);
            values.push(value);
        }
        Ok(values.pop().unwrap())
    }

    #[cfg(test)]
    pub(super) fn encode(&self) -> String {
        match self {
            Self::Empty => "E".to_owned(),
            Self::Any => "A".to_owned(),
            Self::Literal(c) => format!("L({c})"),
            Self::String(s) => format!(
                "S({})",
                s.iter().map(u16::to_string).collect::<Vec<_>>().join(",")
            ),
            Self::Range(lo, hi) => format!("R({lo},{hi})"),
            Self::Union(a, b) => format!("U({},{})", a.encode(), b.encode()),
            Self::Concat(a, b) => format!("C({},{})", a.encode(), b.encode()),
            Self::Intersection(a, b) => format!("I({},{})", a.encode(), b.encode()),
            Self::Complement(a) => format!("N({})", a.encode()),
            Self::Optional(a) => format!("O({})", a.encode()),
            Self::Star(a) => format!("T({})", a.encode()),
            Self::Minimum(n, a) => format!("M({n},{})", a.encode()),
            Self::Bounded(n, m, a) => format!("B({n},{m},{})", a.encode()),
        }
    }
}

// Detach children before normal field destruction so untrusted tree depth never
// becomes native call-stack depth, including partially built trees on parse errors.
impl Drop for Ast {
    fn drop(&mut self) {
        #[allow(
            clippy::vec_box,
            reason = "The worklist owns detached child boxes so AST destruction stays iterative."
        )]
        fn detach(node: &mut Ast, pending: &mut Vec<Box<Ast>>) {
            match node {
                Ast::Union(a, b) | Ast::Concat(a, b) | Ast::Intersection(a, b) => {
                    pending.push(std::mem::replace(a, Box::new(Ast::Empty)));
                    pending.push(std::mem::replace(b, Box::new(Ast::Empty)));
                }
                Ast::Complement(a)
                | Ast::Optional(a)
                | Ast::Star(a)
                | Ast::Minimum(_, a)
                | Ast::Bounded(_, _, a) => {
                    pending.push(std::mem::replace(a, Box::new(Ast::Empty)));
                }
                _ => {}
            }
        }
        let mut pending = Vec::new();
        detach(self, &mut pending);
        while let Some(mut node) = pending.pop() {
            detach(&mut node, &mut pending);
        }
    }
}
