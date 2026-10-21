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
mod java_chars;
mod parse;
mod pattern;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub use check::RuleKind;
pub use eval::{ReadKind, Snapshot};
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

    /// Whether `requester` may read `path` (with `query`, for a query) in the tree `root` with
    /// a REST `GET`.
    pub fn can_read(
        &self,
        root: Option<&Node>,
        path: &Path,
        query: Option<&QueryParams>,
        requester: &Requester<'_>,
    ) -> bool {
        self.can_read_as(root, path, query, ReadKind::Get, requester)
    }

    /// [`Rules::can_read`] for a read of `kind`, which decides the ordering a read without a
    /// query has.
    pub fn can_read_as(
        &self,
        root: Option<&Node>,
        path: &Path,
        query: Option<&QueryParams>,
        kind: ReadKind,
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
                    read_kind: kind,
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
            read_kind: ReadKind::Check,
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
            let mut expr = parse::parse(&source.text).map_err(located)?;
            check::check(&mut expr, kind, wildcards).map_err(located)?;
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

#[cfg(test)]
mod java_chars_tests {
    //! The generated tables against the classes Java 21 printed, for every code unit of the
    //! Basic Multilingual Plane (review r8 M18), and what the reader does with each.

    use super::java_chars;

    /// The fixture's ranges for `name`.
    fn ranges(name: &str) -> Vec<(u32, u32)> {
        let fixture = include_str!("../../tests/fixtures/java21-chars.txt");
        let line = fixture
            .lines()
            .find(|line| line.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("{name} is in the fixture"));
        line.split_whitespace()
            .skip(1)
            .map(|range| {
                let (lo, hi) = range.split_once('-').unwrap();
                (
                    u32::from_str_radix(lo, 16).unwrap(),
                    u32::from_str_radix(hi, 16).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn every_bmp_code_unit_is_classified_as_java_21_classifies_it() {
        type Classify = fn(char) -> bool;
        let classes: [(&str, Classify); 4] = [
            ("identifier_start", java_chars::is_identifier_start),
            ("identifier_part", java_chars::is_identifier_part),
            ("space_separator", java_chars::is_space_separator),
            ("format", java_chars::is_format),
        ];
        for (name, classify) in classes {
            let ranges = ranges(name);
            let mut checked = 0;
            for code in 0..=0xFFFF_u32 {
                let Some(c) = char::from_u32(code) else {
                    continue; // a surrogate is no char here
                };
                let java = ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&code));
                assert_eq!(classify(c), java, "{name} U+{code:04X}");
                checked += 1;
            }
            assert_eq!(checked, 0x1_0000 - 0x800);
        }
    }

    #[test]
    fn every_bmp_code_unit_has_the_digit_value_java_21_reads() {
        let ranges = ranges("decimal_digit");
        for code in 0..=0xFFFF_u32 {
            let Some(c) = char::from_u32(code) else {
                continue;
            };
            let java = ranges
                .iter()
                .find(|&&(lo, hi)| (lo..=hi).contains(&code))
                .map(|&(lo, _)| (code - lo) % 10);
            assert_eq!(java_chars::decimal_digit(c), java, "U+{code:04X}");
        }
        assert_eq!(java_chars::decimal_digit('\u{1d7cf}'), None);
    }

    /// Java's case mappings of every BMP code unit that has one, from the fixture.
    fn case_map(name: &str) -> std::collections::BTreeMap<char, String> {
        let fixture = include_str!("../../tests/fixtures/java21-chars.txt");
        let line = fixture
            .lines()
            .find(|line| line.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("{name} is in the fixture"));
        line.split_whitespace()
            .skip(1)
            .map(|entry| {
                let (from, to) = entry.split_once('>').unwrap();
                let unit = |hex: &str| u16::from_str_radix(hex, 16).unwrap();
                let to: Vec<u16> = to.split(',').map(unit).collect();
                (
                    char::from_u32(u32::from_str_radix(from, 16).unwrap()).unwrap(),
                    String::from_utf16(&to).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn every_code_point_changes_case_as_java_21_changes_it() {
        for (name, lower) in [("lower_map", true), ("upper_map", false)] {
            let java = case_map(name);
            let mut differ = Vec::new();
            for code in 0..=0x10_FFFF_u32 {
                let Some(c) = char::from_u32(code) else {
                    continue;
                };
                let expected = java.get(&c).cloned().unwrap_or_else(|| c.to_string());
                match super::eval::java_case(&c.to_string(), lower) {
                    Some(got) => assert_eq!(got, expected, "{name} U+{code:04X}"),
                    None => differ.push(c),
                }
            }
            // The code points refused are those Rust's tables and Java 21's map differently,
            // and `Σ` in a lowercase, whose result depends on its neighbours.
            for c in differ.into_iter().filter(|&c| !(lower && c == '\u{03A3}')) {
                let rust = if lower {
                    c.to_lowercase().collect::<String>()
                } else {
                    c.to_uppercase().collect::<String>()
                };
                let expected = java.get(&c).cloned().unwrap_or_else(|| c.to_string());
                let other = if lower {
                    c.to_uppercase().collect::<String>()
                } else {
                    c.to_lowercase().collect::<String>()
                };
                let other_java = case_map(if lower { "upper_map" } else { "lower_map" })
                    .get(&c)
                    .cloned()
                    .unwrap_or_else(|| c.to_string());
                assert!(
                    rust != expected || other != other_java,
                    "{name} refuses U+{:04X}, which both map alike",
                    u32::from(c)
                );
            }
        }
    }

    #[test]
    fn capital_sigma_lowercases_as_java_21_only_between_plain_neighbours() {
        // Java 21 makes `Σ` the final `ς` by its word-break iterator; Rust by case-ignorable
        // skipping. They agree when each neighbour is the string's edge, an ASCII space or a
        // cased Latin, Greek or Cyrillic letter, and the rest is an error (review r11 M41).
        for (text, java) in [
            ("\u{03A3}", "\u{03C3}"),
            ("\u{0391}\u{03A3}", "\u{03B1}\u{03C2}"),
            ("\u{0391}\u{03A3}\u{0391}", "\u{03B1}\u{03C3}\u{03B1}"),
            ("\u{0391}\u{03A3} \u{0391}", "\u{03B1}\u{03C2} \u{03B1}"),
            ("a \u{03A3}", "a \u{03C3}"),
            ("\u{03A3}\u{03A3}", "\u{03C3}\u{03C2}"),
            ("\u{0416}\u{03A3}", "\u{0436}\u{03C2}"),
        ] {
            assert_eq!(
                super::eval::java_case(text, true).as_deref(),
                Some(java),
                "{text}"
            );
        }
        for text in [
            "\u{0391}:\u{03A3}",
            "\u{0391}\u{10D50}\u{03A3}",
            "\u{10D50}\u{03A3}",
            "\u{0391}\u{03A3}.",
            "\u{0391}\u{0301}\u{03A3}",
            "1\u{03A3}",
            "\u{0391}\u{03A3}\u{0345}",
        ] {
            assert_eq!(super::eval::java_case(text, true), None, "{text}");
            // Garay maps differently in both directions, so only the others uppercase.
            let garay = text.contains('\u{10D50}');
            assert_eq!(
                super::eval::java_case(text, false).is_some(),
                !garay,
                "{text}"
            );
        }
    }

    #[test]
    fn every_plain_sigma_neighbour_is_cased_and_no_case_ignorable() {
        // A plain neighbour before `Σ` makes it final and one after keeps it medial, as a
        // cased letter does in Java 21 (the recorded `case12` table checks each on the
        // official emulator).
        for c in (0..=0x04FF_u32).filter_map(char::from_u32) {
            if c == ' ' || super::eval::java_case(&format!("{c}\u{03A3}"), true).is_none() {
                continue;
            }
            assert_eq!(
                super::eval::java_case(&format!("{c}\u{03A3}"), true)
                    .unwrap()
                    .chars()
                    .last(),
                Some('\u{03C2}'),
                "{c:?}"
            );
            assert_eq!(
                super::eval::java_case(&format!("\u{03A3}{c}"), true)
                    .unwrap()
                    .chars()
                    .next(),
                Some('\u{03C3}'),
                "{c:?}"
            );
        }
    }

    #[test]
    fn nothing_outside_the_bmp_is_a_name_character() {
        for c in [
            '\u{1d41a}',
            '\u{1d7ce}',
            '\u{10400}',
            '\u{1f600}',
            '\u{e0001}',
        ] {
            assert!(!java_chars::is_identifier_start(c));
            assert!(!java_chars::is_identifier_part(c));
            assert!(!java_chars::is_format(c));
        }
    }
}
