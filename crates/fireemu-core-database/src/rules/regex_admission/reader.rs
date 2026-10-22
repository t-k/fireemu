//! Regex-literal canonical-tree prototype; not wired into production parsing.
//! Input is the literal text after the existing lexer removes format characters.
//! Group parsing uses an explicit frame stack and has no prototype size cutoff.
use super::{Failure, ast::Ast, jar_integer};

struct Reader {
    units: Vec<u16>,
    at: usize,
    ignore_case: bool,
}

fn simple(tree: &Ast) -> bool {
    matches!(tree, Ast::Literal(_) | Ast::String(_))
}

fn string_join(a: Ast, b: Ast) -> Ast {
    fn units(mut tree: Ast) -> Vec<u16> {
        match &mut tree {
            Ast::Literal(c) => vec![*c],
            Ast::String(s) => std::mem::take(s),
            _ => unreachable!(),
        }
    }
    let mut result = units(a);
    result.extend(units(b));
    Ast::String(result)
}

fn concat(mut a: Ast, mut b: Ast) -> Ast {
    if simple(&a) && simple(&b) {
        return string_join(a, b);
    }
    if let Ast::Concat(_, right) = &mut a {
        if simple(right) && simple(&b) {
            let tail = std::mem::replace(right.as_mut(), Ast::Empty);
            **right = string_join(tail, b);
            return a;
        }
    }
    if let Ast::Concat(left, _) = &mut b {
        if simple(&a) && simple(left) {
            let head = std::mem::replace(left.as_mut(), Ast::Empty);
            **left = string_join(a, head);
            return b;
        }
    }
    Ast::Concat(Box::new(a), Box::new(b))
}

impl Reader {
    fn peek(&self) -> Option<u16> {
        self.units.get(self.at).copied()
    }

    fn take(&mut self, unit: u8) -> bool {
        if self.peek() == Some(u16::from(unit)) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Result<u16, Failure> {
        let unit = self.peek().ok_or(Failure::Syntax)?;
        self.at += 1;
        Ok(unit)
    }

    fn expect(&mut self, unit: u8) -> Result<(), Failure> {
        if self.take(unit) {
            Ok(())
        } else {
            Err(Failure::Syntax)
        }
    }

    fn mode_char(&self, unit: u16) -> Result<Ast, Failure> {
        if self.ignore_case {
            Ast::ascii_char(unit)
        } else {
            Ok(Ast::Literal(unit))
        }
    }

    fn mode_range(&self, lo: u16, hi: u16) -> Result<Ast, Failure> {
        if self.ignore_case {
            Ast::ascii_range(lo, hi)
        } else {
            Ok(Ast::Range(lo, hi))
        }
    }

    fn expression(&mut self) -> Result<Ast, Failure> {
        #[derive(Default)]
        struct Frame {
            concatenation: Vec<Ast>,
            branches: Vec<Ast>,
        }
        impl Frame {
            fn push(&mut self, tree: Ast) {
                // Coalesce adjacent simple atoms as they arrive, avoiding quadratic
                // copying when a long literal is finally folded from the right.
                if self.concatenation.last().is_some_and(simple) && simple(&tree) {
                    let left = self.concatenation.pop().unwrap();
                    self.concatenation.push(string_join(left, tree));
                } else {
                    self.concatenation.push(tree);
                }
            }
            fn branch(&mut self) {
                let mut tree = self.concatenation.pop().unwrap();
                while let Some(left) = self.concatenation.pop() {
                    tree = concat(left, tree);
                }
                self.branches.push(tree);
            }
            fn finish(mut self) -> Ast {
                self.branch();
                let mut tree = self.branches.pop().unwrap();
                while let Some(left) = self.branches.pop() {
                    tree = Ast::Union(Box::new(left), Box::new(tree));
                }
                tree
            }
        }
        let mut parents = Vec::new();
        let mut frame = Frame::default();
        loop {
            let mut tree = if self.take(b'(') {
                if self.take(b')') {
                    Ast::String(Vec::new())
                } else {
                    parents.push(frame);
                    frame = Frame::default();
                    continue;
                }
            } else {
                self.atom()?
            };
            loop {
                tree = self.repeat(tree)?;
                frame.push(tree);
                if self.take(b'|') {
                    frame.branch();
                    break;
                }
                if self.peek().is_some_and(|c| c != 41) {
                    break;
                }
                tree = frame.finish();
                if let Some(parent) = parents.pop() {
                    self.expect(b')')?;
                    frame = parent;
                } else {
                    return Ok(tree);
                }
            }
        }
    }

    fn count(&mut self) -> Result<u32, Failure> {
        let start = self.at;
        while self.peek().is_some_and(|c| (48..=57).contains(&c)) {
            self.at += 1;
        }
        if self.at == start {
            return Err(Failure::Syntax);
        }
        let text = String::from_utf16(&self.units[start..self.at]).map_err(|_| Failure::Integer)?;
        jar_integer(&text)
    }

    fn repeat(&mut self, mut tree: Ast) -> Result<Ast, Failure> {
        loop {
            if self.take(b'?') {
                tree = Ast::Optional(Box::new(tree));
            } else if self.take(b'*') {
                tree = Ast::Star(Box::new(tree));
            } else if self.take(b'+') {
                tree = Ast::Minimum(1, Box::new(tree));
            } else if self.take(b'{') {
                let min = self.count()?;
                let max = if self.take(b',') {
                    if self.peek().is_some_and(|c| (48..=57).contains(&c)) {
                        Some(self.count()?)
                    } else {
                        None
                    }
                } else {
                    Some(min)
                };
                self.expect(b'}')?;
                tree = match max {
                    Some(max) => Ast::Bounded(min, max, Box::new(tree)),
                    None => Ast::Minimum(min, Box::new(tree)),
                };
            } else {
                return Ok(tree);
            }
        }
    }

    fn shorthand(&mut self) -> Result<Option<Ast>, Failure> {
        let Some(unit) = self.peek() else {
            return Ok(None);
        };
        let tree = match unit {
            100 | 68 => Ast::Range(48, 57),
            119 | 87 => Ast::Union(
                Box::new(Ast::Union(
                    Box::new(Ast::Range(48, 57)),
                    Box::new(Ast::Range(97, 122)),
                )),
                Box::new(Ast::Union(
                    Box::new(Ast::Range(65, 90)),
                    Box::new(Ast::Literal(95)),
                )),
            ),
            // Existing production shape validation refuses this named-automaton class.
            115 | 83 => return Err(Failure::Syntax),
            _ => return Ok(None),
        };
        self.at += 1;
        Ok(Some(if unit == 68 || unit == 87 {
            Ast::Complement(Box::new(tree))
        } else {
            tree
        }))
    }

    fn escaped_char(&mut self) -> Result<u16, Failure> {
        self.take(b'\\');
        self.next()
    }

    fn class_member(&mut self) -> Result<Ast, Failure> {
        let first = if self.take(b'\\') {
            if let Some(tree) = self.shorthand()? {
                return Ok(tree);
            }
            self.escaped_char()?
        } else {
            self.escaped_char()?
        };
        if self.take(b'-') {
            if self.peek() == Some(93) {
                Ok(Ast::Union(
                    Box::new(self.mode_char(first)?),
                    Box::new(self.mode_char(45)?),
                ))
            } else {
                let last = self.escaped_char()?;
                self.mode_range(first, last)
            }
        } else {
            self.mode_char(first)
        }
    }

    fn class(&mut self) -> Result<Ast, Failure> {
        let negate = self.take(b'^');
        let mut tree = self.class_member()?;
        while self.peek().is_some_and(|c| c != 93) {
            tree = Ast::Union(Box::new(tree), Box::new(self.class_member()?));
        }
        self.expect(b']')?;
        Ok(if negate {
            Ast::Intersection(
                Box::new(Ast::Any),
                Box::new(Ast::Complement(Box::new(tree))),
            )
        } else {
            tree
        })
    }

    fn atom(&mut self) -> Result<Ast, Failure> {
        if self.take(b'.') {
            Ok(Ast::Any)
        } else if self.take(b'[') {
            self.class()
        } else if self.take(b'\\') {
            if let Some(tree) = self.shorthand()? {
                Ok(tree)
            } else {
                let unit = self.next()?;
                self.mode_char(unit)
            }
        } else {
            if matches!(self.peek(), Some(36 | 94)) {
                return Err(Failure::Syntax);
            }
            let unit = self.next()?;
            self.mode_char(unit)
        }
    }
}

pub(super) fn literal(source: &str, ignore_case: bool) -> Result<Ast, Failure> {
    // RegexLiteral performs these textual anchor adjustments before RegExp2 parsing.
    let (prefix, body) = source.strip_prefix('^').map_or((".*", source), |s| ("", s));
    let (body, suffix) = body.strip_suffix('$').map_or((body, ".*"), |s| (s, ""));
    let units: Vec<_> = prefix
        .encode_utf16()
        .chain(body.encode_utf16())
        .chain(suffix.encode_utf16())
        .collect();
    if units.is_empty() {
        return Ok(Ast::String(Vec::new()));
    }
    let mut reader = Reader {
        units,
        at: 0,
        ignore_case,
    };
    let tree = reader.expression()?;
    if reader.at != reader.units.len() {
        return Err(Failure::Syntax);
    }
    Ok(tree)
}
