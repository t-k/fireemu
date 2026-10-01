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

impl Glob {
    /// Compiles `pattern`. Every string is a pattern: what has no meaning is a literal.
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        let chars: Vec<char> = pattern.chars().collect();
        Self {
            program: compile(&scan(&chars)),
        }
    }

    /// Whether `name` matches the pattern in full.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let mut current = Threads::new(self.program.len());
        let mut next = Threads::new(self.program.len());
        current.add(&self.program, 0);
        for c in name.chars() {
            if current.list.is_empty() {
                return false;
            }
            for &pc in &current.list {
                let steps = match &self.program[pc] {
                    Inst::Literal(expected) => *expected == c,
                    Inst::One => c != '/',
                    Inst::Class(ranges, negated) => {
                        c != '/'
                            && (ranges.iter().any(|&(low, high)| low <= c && c <= high) != *negated)
                    }
                    Inst::AnyChar => true,
                    Inst::Split(..) | Inst::Jump(_) | Inst::Match => false,
                };
                if steps {
                    next.add(&self.program, pc + 1);
                }
            }
            std::mem::swap(&mut current, &mut next);
            next.clear();
        }
        current
            .list
            .iter()
            .any(|&pc| self.program[pc] == Inst::Match)
    }
}

/// The instructions that can run at the current point of the name, each listed once.
struct Threads {
    list: Vec<usize>,
    seen: Vec<u32>,
    generation: u32,
}

impl Threads {
    fn new(size: usize) -> Self {
        Self {
            list: Vec::new(),
            seen: vec![0; size],
            generation: 1,
        }
    }

    fn clear(&mut self) {
        self.list.clear();
        self.generation += 1;
    }

    /// Adds `pc` and every instruction reachable from it without consuming a character.
    fn add(&mut self, program: &[Inst], pc: usize) {
        let mut pending = vec![pc];
        while let Some(pc) = pending.pop() {
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
    }
}

/// Reads the pattern into elements. Braces are kept as they stand; [`compile`] decides which of
/// them pair.
fn scan(chars: &[char]) -> Vec<Raw> {
    let members = Members::of(chars);
    let mut raw = Vec::new();
    let mut at = 0;
    // Every pass consumes at least one character, so `chars.len()` passes are the most there can
    // be; the bound keeps a cursor that stopped advancing from growing `raw` without end.
    for _ in 0..=chars.len() {
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
                    at += 2 + chars[at + 2..].iter().take_while(|&&c| c == '*').count();
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
                if let Some((class, next)) = members.class(chars, at) {
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
    raw
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
    fn of(chars: &[char]) -> Self {
        if !chars.contains(&'[') {
            return Self {
                next: Vec::new(),
                close: Vec::new(),
            };
        }
        let next: Vec<Option<usize>> = (0..chars.len())
            .map(|at| read_member(chars, at).map(|(_, after)| after))
            .collect();
        let mut close: Vec<Option<usize>> = vec![None; chars.len()];
        for at in (0..chars.len()).rev() {
            close[at] = if chars[at] == ']' {
                Some(at + 1)
            } else {
                next[at].and_then(|after| close.get(after).copied().flatten())
            };
        }
        Self { next, close }
    }

    /// The set starting at the `[` at `start` and the index after its `]`, or `None` when the
    /// set never closes.
    fn class(&self, chars: &[char], start: usize) -> Option<(Raw, usize)> {
        let mut at = start + 1;
        let negated = matches!(chars.get(at), Some('!' | '^'));
        if negated {
            at += 1;
        }
        // The first member is a member even when it is a `]`.
        let after_first = self.next.get(at).copied().flatten()?;
        let end = self.close.get(after_first).copied().flatten()?;
        let mut ranges = Vec::new();
        let mut member = at;
        let mut first = true;
        // As in `scan`, each pass consumes a character, so the pattern's length bounds the passes.
        for _ in 0..=chars.len() {
            if chars[member] == ']' && !first {
                return Some((Raw::Class(ranges, negated), end));
            }
            first = false;
            let (range, after) = read_member(chars, member)?;
            ranges.push(range);
            member = after;
        }
        None
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
fn compile(raw: &[Raw]) -> Vec<Inst> {
    let mut paired = vec![false; raw.len()];
    let mut open = Vec::new();
    for (index, element) in raw.iter().enumerate() {
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
            Raw::Class(ranges, negated) => program.push(Inst::Class(ranges.clone(), *negated)),
            Raw::Open if paired[index] => {
                let split = program.len();
                program.push(Inst::Split(split + 1, split + 1));
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
                program.push(Inst::Split(next_split + 1, next_split + 1));
                group.split = next_split;
            }
            Raw::Close if paired[index] => {
                let group = groups.pop().expect("a paired `}` has an open group");
                let after = program.len();
                for exit in group.exits {
                    program[exit] = Inst::Jump(after);
                }
            }
            Raw::Open => program.push(Inst::Literal('{')),
            Raw::Close => program.push(Inst::Literal('}')),
            Raw::Comma => program.push(Inst::Literal(',')),
        }
    }
    program.push(Inst::Match);
    program
}
