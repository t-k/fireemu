//! The glob syntax of the JSON API's `matchGlob` list filter.
//!
//! <https://cloud.google.com/storage/docs/json_api/v1/objects/list>: `*` matches any run of
//! characters except `/`, `**` any run including `/`, `?` one character except `/`, `[...]` one
//! character of a set or range (`[!...]` and `[^...]` negate it; a set never matches `/`),
//! `{a,b}` any of the alternatives, and `\` takes the next character literally. Only the pattern
//! `dir/*` was recorded in production; every other construct follows the documentation. An
//! unterminated `[` or `{` is taken literally (production's answer to one was not recorded), as
//! is a `}` that closes nothing and a `,` outside braces.
//!
//! A pattern is compiled once into a small program and matched by simulating all of its states
//! side by side, one name character at a time: the time is the program length times the name
//! length, whatever the pattern, and neither the compiler nor the matcher recurses, so a pattern
//! as long as a request line allows cannot exhaust the time or the stack.

/// One instruction of a compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Inst {
    /// One given character.
    Literal(char),
    /// `?`: one character except `/`.
    One,
    /// `[...]`: one character except `/` that is (or, negated, is not) in the ranges.
    Class(Vec<(char, char)>, bool),
    /// One character of any kind (the body of a `**` loop).
    AnyChar,
    /// Continue at either of two instructions.
    Split(usize, usize),
    /// Continue at one instruction.
    Jump(usize),
    /// The whole pattern has matched.
    Match,
}

/// One element of a pattern, before braces are paired.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Raw {
    Literal(char),
    /// `*`.
    Segment,
    /// `**`.
    Any,
    /// `?`.
    One,
    /// `[...]`.
    Class(Vec<(char, char)>, bool),
    /// `{`.
    Open,
    /// `}`.
    Close,
    /// `,`.
    Comma,
}

/// A compiled `matchGlob` pattern.
#[derive(Debug, Clone)]
pub struct Glob {
    program: Vec<Inst>,
}

/// Whether `name` matches the glob `pattern` in full.
#[must_use]
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    Glob::new(pattern).matches(name)
}

/// A discarded computation, distinct from a pattern that does not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

/// Primitive matcher work observed at cancellation polls.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchPhase {
    /// Initializes the finite state vectors.
    Threads,
    /// Expands epsilon transitions.
    Epsilon,
    /// Walks active instructions for a name character.
    States,
    /// Compares a character with class ranges.
    Ranges,
    /// Tests the remaining accepting instructions.
    Finish,
}

/// Maximum primitive steps between cooperative cancellation polls.
pub const CANCELLATION_INTERVAL: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Characters,
    Members,
    Scan,
    Class,
    Pair,
    Compile,
    ClassCopy,
    Exits,
    Threads,
    Epsilon,
    States,
    Ranges,
    Finish,
}

struct WorkBudget<'a> {
    remaining: usize,
    cancelled: &'a mut dyn FnMut(Phase) -> bool,
}

impl<'a> WorkBudget<'a> {
    fn new(cancelled: &'a mut dyn FnMut(Phase) -> bool) -> Self {
        Self {
            remaining: 0,
            cancelled,
        }
    }

    fn step(&mut self, phase: Phase) -> Result<(), Cancelled> {
        if self.remaining == 0 {
            if (self.cancelled)(phase) {
                return Err(Cancelled);
            }
            self.remaining = CANCELLATION_INTERVAL;
        }
        self.remaining -= 1;
        Ok(())
    }
}

impl Glob {
    /// Compiles `pattern`. Every string is a pattern: what has no meaning is a literal.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self::try_new(pattern, &|| false).expect("a never-cancelled compiler completes")
    }

    /// Compiles while polling cancellation within character, class and brace processing.
    pub fn try_new(pattern: &str, cancelled: &dyn Fn() -> bool) -> Result<Self, Cancelled> {
        Self::with_budget(pattern, &mut WorkBudget::new(&mut |_| cancelled()))
    }

    fn with_budget(pattern: &str, budget: &mut WorkBudget<'_>) -> Result<Self, Cancelled> {
        let mut chars = Vec::new();
        for character in pattern.chars() {
            budget.step(Phase::Characters)?;
            chars.push(character);
        }
        Ok(Self {
            program: compile(&scan(&chars, budget)?, budget)?,
        })
    }

    /// Whether `name` matches the pattern in full.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        self.try_matches(name, &|| false)
            .expect("a never-cancelled matcher completes")
    }

    /// Matches while polling cancellation inside state and epsilon expansion work.
    pub fn try_matches(&self, name: &str, cancelled: &dyn Fn() -> bool) -> Result<bool, Cancelled> {
        self.try_matches_observed(name, cancelled, &|_| {})
    }

    /// The cooperative matcher with optional primitive-phase observations.
    #[doc(hidden)]
    pub fn try_matches_observed(
        &self,
        name: &str,
        cancelled: &dyn Fn() -> bool,
        observe: &dyn Fn(MatchPhase),
    ) -> Result<bool, Cancelled> {
        self.matches_with_budget(
            name,
            &mut WorkBudget::new(&mut |phase| {
                observe(match phase {
                    Phase::Threads => MatchPhase::Threads,
                    Phase::Epsilon => MatchPhase::Epsilon,
                    Phase::States => MatchPhase::States,
                    Phase::Ranges => MatchPhase::Ranges,
                    Phase::Finish => MatchPhase::Finish,
                    _ => unreachable!("only matcher phases run during matching"),
                });
                cancelled()
            }),
        )
    }

    fn matches_with_budget(
        &self,
        name: &str,
        budget: &mut WorkBudget<'_>,
    ) -> Result<bool, Cancelled> {
        let mut current = Threads::new(self.program.len(), budget)?;
        let mut next = Threads::new(self.program.len(), budget)?;
        current.add(&self.program, 0, budget)?;
        for c in name.chars() {
            budget.step(Phase::States)?;
            if current.list.is_empty() {
                return Ok(false);
            }
            for &pc in &current.list {
                budget.step(Phase::States)?;
                let steps = match &self.program[pc] {
                    Inst::Literal(expected) => *expected == c,
                    Inst::One => c != '/',
                    Inst::Class(ranges, negated) => {
                        let mut included = false;
                        if c != '/' {
                            for &(low, high) in ranges {
                                budget.step(Phase::Ranges)?;
                                if low <= c && c <= high {
                                    included = true;
                                    break;
                                }
                            }
                        }
                        c != '/' && (included != *negated)
                    }
                    Inst::AnyChar => true,
                    Inst::Split(..) | Inst::Jump(_) | Inst::Match => false,
                };
                if steps {
                    next.add(&self.program, pc + 1, budget)?;
                }
            }
            std::mem::swap(&mut current, &mut next);
            next.clear();
        }
        for &pc in &current.list {
            budget.step(Phase::Finish)?;
            if self.program[pc] == Inst::Match {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The instructions that can run at the current point of the name, each listed once.
struct Threads {
    list: Vec<usize>,
    seen: Vec<u32>,
    generation: u32,
}

impl Threads {
    fn new(size: usize, budget: &mut WorkBudget<'_>) -> Result<Self, Cancelled> {
        let mut seen = Vec::with_capacity(size);
        for _ in 0..size {
            budget.step(Phase::Threads)?;
            seen.push(0);
        }
        Ok(Self {
            list: Vec::new(),
            seen,
            generation: 1,
        })
    }

    fn clear(&mut self) {
        self.list.clear();
        self.generation += 1;
    }

    /// Adds `pc` and every instruction reachable from it without consuming a character.
    fn add(
        &mut self,
        program: &[Inst],
        pc: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<(), Cancelled> {
        let mut pending = vec![pc];
        while let Some(pc) = pending.pop() {
            budget.step(Phase::Epsilon)?;
            if self.seen[pc] == self.generation {
                continue;
            }
            self.seen[pc] = self.generation;
            self.list.push(pc);
            match &program[pc] {
                Inst::Jump(target) => pending.push(*target),
                Inst::Split(first, second) => {
                    pending.push(*second);
                    pending.push(*first);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Reads the pattern into elements. Braces are kept as they stand; [`compile`] decides which of
/// them pair.
fn scan(chars: &[char], budget: &mut WorkBudget<'_>) -> Result<Vec<Raw>, Cancelled> {
    let members = Members::of(chars, budget)?;
    let mut raw = Vec::new();
    let mut at = 0;
    // Every pass consumes at least one character, so `chars.len()` passes are the most there can
    // be; the bound keeps a cursor that stopped advancing from growing `raw` without end.
    for _ in 0..=chars.len() {
        budget.step(Phase::Scan)?;
        let Some(&c) = chars.get(at) else { break };
        match c {
            '\\' => {
                if let Some(&escaped) = chars.get(at + 1) {
                    raw.push(Raw::Literal(escaped));
                    at += 2;
                } else {
                    raw.push(Raw::Literal('\\'));
                    at += 1;
                }
            }
            '*' => {
                if chars.get(at + 1) == Some(&'*') {
                    raw.push(Raw::Any);
                    at += 2;
                    while chars.get(at) == Some(&'*') {
                        budget.step(Phase::Scan)?;
                        at += 1;
                    }
                } else {
                    raw.push(Raw::Segment);
                    at += 1;
                }
            }
            '?' => {
                raw.push(Raw::One);
                at += 1;
            }
            '[' => {
                if let Some((class, next)) = members.class(chars, at, budget)? {
                    raw.push(class);
                    at = next;
                } else {
                    raw.push(Raw::Literal('['));
                    at += 1;
                }
            }
            '{' => {
                raw.push(Raw::Open);
                at += 1;
            }
            '}' => {
                raw.push(Raw::Close);
                at += 1;
            }
            ',' => {
                raw.push(Raw::Comma);
                at += 1;
            }
            other => {
                raw.push(Raw::Literal(other));
                at += 1;
            }
        }
    }
    Ok(raw)
}

/// Where the members of every `[...]` set that could start in the pattern lead, computed once
/// for the whole pattern so that a set that never closes costs one step per character and not a
/// scan to the end of the pattern each time.
struct Members {
    /// The index after the member that starts at each index (`None`: it is cut off).
    next: Vec<Option<usize>>,
    /// The index after the `]` that closes a set when a member starts at each index (`None`: the
    /// set never closes).
    close: Vec<Option<usize>>,
}

impl Members {
    fn of(chars: &[char], budget: &mut WorkBudget<'_>) -> Result<Self, Cancelled> {
        let mut has_class = false;
        for &c in chars {
            budget.step(Phase::Members)?;
            if c == '[' {
                has_class = true;
                break;
            }
        }
        if !has_class {
            return Ok(Self {
                next: Vec::new(),
                close: Vec::new(),
            });
        }
        let mut next = Vec::with_capacity(chars.len());
        for at in 0..chars.len() {
            budget.step(Phase::Members)?;
            next.push(read_member(chars, at).map(|(_, after)| after));
        }
        let mut close = Vec::with_capacity(chars.len());
        for _ in 0..chars.len() {
            budget.step(Phase::Members)?;
            close.push(None);
        }
        for at in (0..chars.len()).rev() {
            budget.step(Phase::Members)?;
            close[at] = if chars[at] == ']' {
                Some(at + 1)
            } else {
                next[at].and_then(|after| close.get(after).copied().flatten())
            };
        }
        Ok(Self { next, close })
    }

    /// The set starting at the `[` at `start` and the index after its `]`, or `None` when the
    /// set never closes.
    fn class(
        &self,
        chars: &[char],
        start: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Option<(Raw, usize)>, Cancelled> {
        let mut at = start + 1;
        let negated = matches!(chars.get(at), Some('!' | '^'));
        if negated {
            at += 1;
        }
        // The first member is a member even when it is a `]`.
        let Some(after_first) = self.next.get(at).copied().flatten() else {
            return Ok(None);
        };
        let Some(end) = self.close.get(after_first).copied().flatten() else {
            return Ok(None);
        };
        let mut ranges = Vec::new();
        let mut member = at;
        let mut first = true;
        // As in `scan`, each pass consumes a character, so the pattern's length bounds the passes.
        for _ in 0..=chars.len() {
            budget.step(Phase::Class)?;
            if chars[member] == ']' && !first {
                return Ok(Some((Raw::Class(ranges, negated), end)));
            }
            first = false;
            let Some((range, after)) = read_member(chars, member) else {
                return Ok(None);
            };
            ranges.push(range);
            member = after;
        }
        Ok(None)
    }
}

/// The member of a set that starts at `at`, as the range of characters it stands for, and the
/// index after it: a character, an escaped character, or `low-high` with either end escaped.
fn read_member(chars: &[char], at: usize) -> Option<((char, char), usize)> {
    let c = *chars.get(at)?;
    let (low, mut at) = if c == '\\' {
        (*chars.get(at + 1)?, at + 2)
    } else {
        (c, at + 1)
    };
    if chars.get(at) == Some(&'-') && chars.get(at + 1).is_some_and(|&next| next != ']') {
        let mut high = chars[at + 1];
        at += 2;
        if high == '\\' {
            high = *chars.get(at)?;
            at += 1;
        }
        Some(((low, high), at))
    } else {
        Some(((low, low), at))
    }
}

/// A pair of braces being compiled: the split that chooses between its alternatives, and the
/// jumps that leave each finished alternative.
struct Group {
    split: usize,
    exits: Vec<usize>,
}

/// Turns the elements into a program. A `{` pairs with the `}` that closes it (the nearest
/// unpaired `{` before it); one that nothing closes is a literal, as is a `}` that closes
/// nothing, and a `,` is a separator only inside a pair.
fn compile(raw: &[Raw], budget: &mut WorkBudget<'_>) -> Result<Vec<Inst>, Cancelled> {
    let mut paired = Vec::with_capacity(raw.len());
    for _ in raw {
        budget.step(Phase::Pair)?;
        paired.push(false);
    }
    let mut open = Vec::new();
    for (index, element) in raw.iter().enumerate() {
        budget.step(Phase::Pair)?;
        match element {
            Raw::Open => open.push(index),
            Raw::Close => {
                if let Some(opener) = open.pop() {
                    paired[opener] = true;
                    paired[index] = true;
                }
            }
            _ => {}
        }
    }

    let mut program: Vec<Inst> = Vec::new();
    let mut groups: Vec<Group> = Vec::new();
    for (index, element) in raw.iter().enumerate() {
        budget.step(Phase::Compile)?;
        match element {
            Raw::Literal(c) => program.push(Inst::Literal(*c)),
            Raw::Segment | Raw::Any => {
                let start = program.len();
                program.push(Inst::Split(start + 1, start + 3));
                program.push(if *element == Raw::Any {
                    Inst::AnyChar
                } else {
                    Inst::Class(vec![('/', '/')], true)
                });
                program.push(Inst::Jump(start));
            }
            Raw::One => program.push(Inst::One),
            Raw::Class(ranges, negated) => {
                let mut copied = Vec::with_capacity(ranges.len());
                for &range in ranges {
                    budget.step(Phase::ClassCopy)?;
                    copied.push(range);
                }
                program.push(Inst::Class(copied, *negated));
            }
            Raw::Open if paired[index] => {
                let split = program.len();
                // Replaced by a split when the pair has a second alternative.
                program.push(Inst::Jump(split + 1));
                groups.push(Group {
                    split,
                    exits: Vec::new(),
                });
            }
            Raw::Comma if !groups.is_empty() => {
                let here = program.len();
                let group = groups.last_mut().expect("a group is open");
                group.exits.push(here);
                program.push(Inst::Jump(here));
                let next_split = program.len();
                program[group.split] = Inst::Split(group.split + 1, next_split);
                program.push(Inst::Jump(next_split + 1));
                group.split = next_split;
            }
            Raw::Close if paired[index] => {
                let group = groups.pop().expect("a paired `}` has an open group");
                let after = program.len();
                for exit in group.exits {
                    budget.step(Phase::Exits)?;
                    program[exit] = Inst::Jump(after);
                }
            }
            Raw::Open => program.push(Inst::Literal('{')),
            Raw::Close => program.push(Inst::Literal('}')),
            Raw::Comma => program.push(Inst::Literal(',')),
        }
    }
    program.push(Inst::Match);
    Ok(program)
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn cancelled_compile_is_not_a_compiled_pattern() {
        assert!(matches!(
            Glob::try_new(&"*{,}".repeat(20_000), &|| true),
            Err(Cancelled)
        ));
    }

    #[test]
    fn cancelled_match_is_not_a_false_match() {
        let glob = Glob::new(&format!("{}z", "*{,}".repeat(200)));
        assert_eq!(
            glob.try_matches(&"x".repeat(1000), &|| true),
            Err(Cancelled)
        );
    }
    #[test]
    fn cancellation_polls_every_compile_phase() {
        let class = format!("[{}]", "a".repeat(4096));
        let alternatives = format!("{{{}}}", vec!["x"; 4096].join(","));
        for phase in [
            Phase::Characters,
            Phase::Members,
            Phase::Scan,
            Phase::Class,
            Phase::Pair,
            Phase::Compile,
            Phase::ClassCopy,
            Phase::Exits,
        ] {
            let pattern = if matches!(phase, Phase::Class | Phase::ClassCopy | Phase::Members) {
                &class
            } else {
                &alternatives
            };
            let mut polls = 0;
            let result = Glob::with_budget(
                pattern,
                &mut WorkBudget::new(&mut |at| {
                    if at == phase {
                        polls += 1;
                    }
                    at == phase && polls == 2
                }),
            );
            assert!(matches!(result, Err(Cancelled)), "{phase:?}: {polls} polls");
        }
    }

    #[test]
    fn cancellation_polls_every_match_phase() {
        let dense = Glob::new(&format!("{}z", "*{,}".repeat(4096)));
        let class = Glob::new(&format!("[{}]", "a".repeat(4096)));
        for phase in [
            Phase::Threads,
            Phase::Epsilon,
            Phase::States,
            Phase::Ranges,
            Phase::Finish,
        ] {
            let (glob, name) = match phase {
                Phase::Ranges => (&class, "z"),
                Phase::Finish => (&dense, ""),
                _ => (&dense, "xx"),
            };
            let mut polls = 0;
            let result = glob.matches_with_budget(
                name,
                &mut WorkBudget::new(&mut |at| {
                    if at == phase {
                        polls += 1;
                    }
                    at == phase && polls == 2
                }),
            );
            assert_eq!(result, Err(Cancelled), "{phase:?}: {polls} polls");
        }
    }

    #[test]
    fn cancellation_interval_bounds_primitive_work() {
        let count = std::cell::Cell::new(0);
        let cancelled_at = std::cell::Cell::new(None);
        let mut callback = |_| {
            if count.get() >= 17 {
                cancelled_at.set(Some(count.get()));
                true
            } else {
                false
            }
        };
        let mut budget = WorkBudget::new(&mut callback);
        for step in 0..1000 {
            count.set(step);
            if budget.step(Phase::States).is_err() {
                break;
            }
        }
        assert_eq!(cancelled_at.get(), Some(CANCELLATION_INTERVAL));
    }
}
