//! Realtime Database Security Rules: the rules tree, its static check, and the read and
//! write decisions, as the official emulator (firebase-database-emulator v4.11.2) makes them.
//!
//! - `.read` and `.write` cascade: the first rule that is true on the way from the root down
//!   to the location allows, and a rule further down cannot take it back.
//! - `.validate` does not cascade. A write must satisfy the `.validate` rule of every node it
//!   leaves non-null on the way from the root to the written location and below it.
//! - An exact key matches before a `$wildcard`, which binds the key to its name.
//!
//! The rules file is JSON; the adapter reads it and hands over a [`RuleSpec`] whose
//! expressions carry the line and column of each character, so an error names the place
//! in the file, as the official emulator does.

mod check;
mod eval;
mod parse;
mod pattern;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use check::RuleKind;
pub use eval::Snapshot;
pub use parse::ExprError;

use crate::json::Json;
use crate::node::Node;
use crate::path::Path;
use crate::query::QueryParams;

/// A rule expression as the rules file spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceExpr {
    /// The expression.
    pub text: String,
    /// The line and column (both from 1) of each character of `text` in the rules file,
    /// and one more entry for the position just after it.
    pub positions: Vec<(usize, usize)>,
}

/// A rule: a boolean, or an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// `true` or `false`.
    Bool(bool),
    /// An expression string.
    Expr(SourceExpr),
}

/// One level of the rules file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSpec {
    /// `.read`
    pub read: Option<RuleSource>,
    /// `.write`
    pub write: Option<RuleSource>,
    /// `.validate`
    pub validate: Option<RuleSource>,
    /// `.indexOn`
    pub index_on: Vec<String>,
    /// The levels below, by key; a key starting with `$` is a wildcard.
    pub children: BTreeMap<String, RuleSpec>,
}

/// An error in a rules file, where the official emulator reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesError {
    /// The line, from 1.
    pub line: usize,
    /// The column, from 1.
    pub column: usize,
    /// The message.
    pub message: String,
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

#[derive(Debug, Clone)]
enum Rule {
    Const(bool),
    Expr(parse::Expr),
}

#[derive(Debug, Clone, Default)]
struct RuleNode {
    read: Option<Rule>,
    write: Option<Rule>,
    validate: Option<Rule>,
    index_on: Vec<String>,
    children: BTreeMap<String, RuleNode>,
    wildcard: Option<(String, Box<RuleNode>)>,
}

/// Compiled rules.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    root: RuleNode,
}

/// The stack of the thread that parses and checks rules.
const COMPILE_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Who asks, and when.
pub struct Requester<'a> {
    /// `auth`: the claims as the server shows them (`uid`, `provider`, `token`), or null.
    pub auth: &'a Json,
    /// `now`, in milliseconds.
    pub now: i64,
}

impl Rules {
    /// Checks and compiles a rules tree. Parsing and checking recurse once per level of
    /// nesting, which the bounds let reach a few thousand frames in a debug build, so they run
    /// on a thread of their own with room for that, whatever the caller's stack.
    pub fn compile(spec: &RuleSpec) -> Result<Self, RulesError> {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("rules-compile".to_owned())
                .stack_size(COMPILE_STACK_BYTES)
                .spawn_scoped(scope, || compile_node(spec, &BTreeSet::new()))
                .map_err(|error| RulesError {
                    line: 1,
                    column: 1,
                    message: format!("Could not start checking the rules: {error}"),
                })?
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                .map(|root| Self { root })
        })
    }

    /// Whether `requester` may read `path` (with `query`, for a query) in the tree `root`.
    pub fn can_read(
        &self,
        root: Option<&Node>,
        path: &Path,
        query: Option<&QueryParams>,
        requester: &Requester<'_>,
    ) -> bool {
        let mut wildcards = BTreeMap::new();
        let mut node = Some(&self.root);
        let mut at = Path::root();
        let mut keys = path.keys().iter();
        while let Some(rule_node) = node {
            if let Some(rule) = &rule_node.read {
                let scope = eval::Scope {
                    auth: requester.auth,
                    now: requester.now,
                    root: Snapshot {
                        root,
                        path: Path::root(),
                    },
                    data: Snapshot {
                        root,
                        path: at.clone(),
                    },
                    new_data: None,
                    query,
                    wildcards: &wildcards,
                };
                if run(rule, &scope) {
                    return true;
                }
            }
            let Some(key) = keys.next() else {
                return false;
            };
            node = descend(rule_node, key, &mut wildcards);
            at = at.child(key);
        }
        false
    }

    /// Whether `requester` may make the write that turns the tree `before` into `after`,
    /// at the locations `written` (one for a set, one per entry for an update).
    pub fn can_write(
        &self,
        before: Option<&Node>,
        after: Option<&Node>,
        written: &[Path],
        requester: &Requester<'_>,
    ) -> bool {
        // A priority belongs to its node: a write of `<path>/.priority` is judged as a write
        // of `<path>`, never through a `$wildcard` below it (review M3).
        let written: Vec<Path> = written
            .iter()
            .map(|path| {
                if path.is_priority() {
                    path.parent().unwrap_or_else(Path::root)
                } else {
                    path.clone()
                }
            })
            .collect();
        written
            .iter()
            .all(|path| self.write_allowed(before, after, path, requester))
            && written
                .iter()
                .all(|path| self.validates(before, after, path, requester))
    }

    /// The `.indexOn` names declared for `path`.
    pub fn index_on(&self, path: &Path) -> Vec<String> {
        let mut wildcards = BTreeMap::new();
        let mut node = &self.root;
        for key in path.keys() {
            match descend(node, key, &mut wildcards) {
                Some(next) => node = next,
                None => return Vec::new(),
            }
        }
        node.index_on.clone()
    }

    fn scope<'a>(
        before: Option<&'a Node>,
        after: Option<&'a Node>,
        at: &Path,
        requester: &Requester<'a>,
        wildcards: &'a BTreeMap<String, String>,
    ) -> eval::Scope<'a> {
        eval::Scope {
            auth: requester.auth,
            now: requester.now,
            root: Snapshot {
                root: before,
                path: Path::root(),
            },
            data: Snapshot {
                root: before,
                path: at.clone(),
            },
            new_data: Some(Snapshot {
                root: after,
                path: at.clone(),
            }),
            query: None,
            wildcards,
        }
    }

    fn write_allowed(
        &self,
        before: Option<&Node>,
        after: Option<&Node>,
        path: &Path,
        requester: &Requester<'_>,
    ) -> bool {
        let mut wildcards = BTreeMap::new();
        let mut node = Some(&self.root);
        let mut at = Path::root();
        let mut keys = path.keys().iter();
        while let Some(rule_node) = node {
            if let Some(rule) = &rule_node.write {
                let scope = Self::scope(before, after, &at, requester, &wildcards);
                if run(rule, &scope) {
                    return true;
                }
            }
            let Some(key) = keys.next() else {
                return false;
            };
            node = descend(rule_node, key, &mut wildcards);
            at = at.child(key);
        }
        false
    }

    /// The `.validate` rules on the way to `path` and in the new data below it, for every
    /// node the write leaves non-null.
    fn validates(
        &self,
        before: Option<&Node>,
        after: Option<&Node>,
        path: &Path,
        requester: &Requester<'_>,
    ) -> bool {
        let mut wildcards = BTreeMap::new();
        let mut node = &self.root;
        let mut at = Path::root();
        for key in path.keys() {
            if !Self::validate_here(node, before, after, &at, requester, &wildcards) {
                return false;
            }
            match descend(node, key, &mut wildcards) {
                Some(next) => node = next,
                None => return true,
            }
            at = at.child(key);
        }
        Self::validate_below(node, before, after, &at, requester, &mut wildcards)
    }

    fn validate_here(
        node: &RuleNode,
        before: Option<&Node>,
        after: Option<&Node>,
        at: &Path,
        requester: &Requester<'_>,
        wildcards: &BTreeMap<String, String>,
    ) -> bool {
        let Some(rule) = &node.validate else {
            return true;
        };
        if after.and_then(|r| r.descendant(at)).is_none() {
            return true;
        }
        run(rule, &Self::scope(before, after, at, requester, wildcards))
    }

    fn validate_below(
        node: &RuleNode,
        before: Option<&Node>,
        after: Option<&Node>,
        at: &Path,
        requester: &Requester<'_>,
        wildcards: &mut BTreeMap<String, String>,
    ) -> bool {
        if !Self::validate_here(node, before, after, at, requester, wildcards) {
            return false;
        }
        let Some(written) = after.and_then(|r| r.descendant(at)) else {
            return true;
        };
        let crate::node::Content::Children(children) = &written.content else {
            return true;
        };
        for key in children.keys() {
            let mut bound = wildcards.clone();
            let Some(child) = descend(node, key, &mut bound) else {
                continue;
            };
            if !Self::validate_below(child, before, after, &at.child(key), requester, &mut bound) {
                return false;
            }
        }
        true
    }
}

fn run(rule: &Rule, scope: &eval::Scope<'_>) -> bool {
    match rule {
        Rule::Const(b) => *b,
        Rule::Expr(expr) => eval::allows(expr, scope),
    }
}

/// The rules level for `key` below `node`: the exact key, else the wildcard, which binds.
fn descend<'a>(
    node: &'a RuleNode,
    key: &str,
    wildcards: &mut BTreeMap<String, String>,
) -> Option<&'a RuleNode> {
    if let Some(child) = node.children.get(key) {
        return Some(child);
    }
    let (name, child) = node.wildcard.as_ref()?;
    wildcards.insert(name.clone(), key.to_owned());
    Some(child)
}

fn compile_rule(
    source: Option<&RuleSource>,
    kind: RuleKind,
    wildcards: &BTreeSet<String>,
) -> Result<Option<Rule>, RulesError> {
    let Some(source) = source else {
        return Ok(None);
    };
    match source {
        RuleSource::Bool(b) => Ok(Some(Rule::Const(*b))),
        RuleSource::Expr(source) => {
            let located = |error: ExprError| {
                let (line, column) = source
                    .positions
                    .get(error.at)
                    .or(source.positions.last())
                    .copied()
                    .unwrap_or((1, 1));
                RulesError {
                    line,
                    column,
                    message: error.message,
                }
            };
            let expr = parse::parse(&source.text).map_err(located)?;
            check::check(&expr, kind, wildcards).map_err(located)?;
            Ok(Some(Rule::Expr(expr)))
        }
    }
}

fn compile_node(spec: &RuleSpec, wildcards: &BTreeSet<String>) -> Result<RuleNode, RulesError> {
    let mut node = RuleNode {
        read: compile_rule(spec.read.as_ref(), RuleKind::Read, wildcards)?,
        write: compile_rule(spec.write.as_ref(), RuleKind::Write, wildcards)?,
        validate: compile_rule(spec.validate.as_ref(), RuleKind::Validate, wildcards)?,
        index_on: spec.index_on.clone(),
        ..RuleNode::default()
    };
    for (key, child) in &spec.children {
        if let Some(name) = key.strip_prefix('$').map(|_| key.clone()) {
            let mut inner = wildcards.clone();
            inner.insert(name.clone());
            node.wildcard = Some((name, Box::new(compile_node(child, &inner)?)));
        } else {
            node.children
                .insert(key.clone(), compile_node(child, wildcards)?);
        }
    }
    Ok(node)
}
