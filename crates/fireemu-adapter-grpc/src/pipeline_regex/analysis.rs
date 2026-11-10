//! Validation and rewrite of recorded pipeline regex syntax.

use fireemu_core_firestore::pipeline_exec::{RegexError, Unrecorded};
use regex_syntax::ast::{self, Ast, Visitor};

pub(super) struct Analysis {
    pub(super) pattern: String,
    pub(super) capture_groups: usize,
}

fn class_body(kind: &ast::ClassPerlKind) -> &'static str {
    match kind {
        ast::ClassPerlKind::Digit => "0-9",
        ast::ClassPerlKind::Word => "0-9A-Za-z_",
        ast::ClassPerlKind::Space => r"\t\n\x0B\x0C\r\x20",
    }
}

fn literal_allowed(literal: &ast::Literal) -> bool {
    matches!(
        literal.kind,
        ast::LiteralKind::Verbatim
            | ast::LiteralKind::Meta
            | ast::LiteralKind::Special(ast::SpecialLiteralKind::Tab)
            | ast::LiteralKind::HexFixed(ast::HexLiteralKind::X)
            | ast::LiteralKind::HexBrace(ast::HexLiteralKind::X)
    )
}

fn counterparts(start: char, end: char) -> String {
    let mut result = String::new();
    for (low, high, upper) in [('a', 'z', true), ('A', 'Z', false)] {
        let first = start.max(low);
        let last = end.min(high);
        if first <= last {
            let convert = |c: char| {
                if upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            };
            result.push(convert(first));
            if first != last {
                result.push('-');
                result.push(convert(last));
            }
        }
    }
    result
}

/// Whether a `U` flag appears and whether the pattern holds anything that flag could change.
#[derive(Default)]
struct Ungreedy {
    flag_present: bool,
    sensitive: bool,
}

struct Walker<'a> {
    pattern: &'a str,
    edits: Vec<(usize, usize, String)>,
    flags: Vec<bool>,
    capture_groups: usize,
    refused: bool,
    unobserved: bool,
    ungreedy: Ungreedy,
}

impl Walker<'_> {
    fn edit(&mut self, span: &ast::Span, replacement: String) {
        self.edits
            .push((span.start.offset, span.end.offset, replacement));
    }

    fn insensitive(&self) -> bool {
        self.flags.last().copied().unwrap_or(false)
    }

    fn flags(&mut self, flags: &ast::Flags, standalone: bool, span: &ast::Span) {
        use ast::{Flag, FlagsItemKind};
        let items = &flags.items;
        let allowed = if standalone {
            matches!(items.as_slice(), [item] if matches!(item.kind, FlagsItemKind::Flag(Flag::CaseInsensitive | Flag::DotMatchesNewLine | Flag::Unicode | Flag::SwapGreed | Flag::MultiLine)))
                || matches!(items.as_slice(), [neg, item] if matches!(neg.kind, FlagsItemKind::Negation) && matches!(item.kind, FlagsItemKind::Flag(Flag::CaseInsensitive | Flag::Unicode)))
        } else {
            items.is_empty()
                || matches!(items.as_slice(), [item] if matches!(item.kind, FlagsItemKind::Flag(Flag::CaseInsensitive)))
        };
        self.unobserved |= !allowed;
        let mut negated = false;
        let mut wrote_negation = false;
        let mut kept = String::new();
        for item in items {
            match item.kind {
                FlagsItemKind::Negation => negated = true,
                FlagsItemKind::Flag(flag) => {
                    match flag {
                        Flag::CaseInsensitive => {
                            if let Some(state) = self.flags.last_mut() {
                                *state = !negated;
                            }
                        }
                        Flag::MultiLine if !negated => self.refused = true,
                        Flag::SwapGreed => self.ungreedy.flag_present = true,
                        _ => {}
                    }
                    let letter = match flag {
                        Flag::DotMatchesNewLine => Some('s'),
                        Flag::IgnoreWhitespace => Some('x'),
                        Flag::CRLF => Some('R'),
                        _ => None,
                    };
                    if let Some(letter) = letter {
                        if negated && !wrote_negation {
                            kept.push('-');
                            wrote_negation = true;
                        }
                        kept.push(letter);
                    }
                }
            }
        }
        let replacement = if standalone && !kept.is_empty() {
            format!("(?{kept})")
        } else {
            kept
        };
        self.edit(span, replacement);
    }

    fn perl(&mut self, class: &ast::ClassPerl, inside: bool) {
        let body = class_body(&class.kind);
        let replacement = if class.negated {
            format!("[^{body}]")
        } else if inside {
            body.to_owned()
        } else {
            format!("[{body}]")
        };
        self.edit(&class.span, replacement);
    }
}

impl Visitor for Walker<'_> {
    type Output = Self;
    type Err = RegexError;

    fn finish(self) -> Result<Self::Output, Self::Err> {
        Ok(self)
    }

    fn visit_pre(&mut self, node: &Ast) -> Result<(), Self::Err> {
        use ast::{AssertionKind, GroupKind};
        match node {
            Ast::Group(group) => {
                self.flags.push(self.insensitive());
                match &group.kind {
                    GroupKind::CaptureIndex(_) => self.capture_groups += 1,
                    GroupKind::CaptureName { starts_with_p, .. } => {
                        self.capture_groups += 1;
                        self.unobserved |= !starts_with_p;
                    }
                    GroupKind::NonCapturing(flags) => self.flags(flags, false, &flags.span),
                }
            }
            Ast::Flags(flags) => self.flags(&flags.flags, true, &flags.span),
            Ast::Literal(literal) => {
                self.unobserved |= !literal_allowed(literal);
                if self.insensitive() && literal.c.is_ascii_alphabetic() {
                    self.edit(
                        &literal.span,
                        format!(
                            "[{}{}]",
                            literal.c.to_ascii_lowercase(),
                            literal.c.to_ascii_uppercase()
                        ),
                    );
                }
            }
            Ast::Assertion(assertion) => {
                let replacement = match assertion.kind {
                    AssertionKind::WordBoundary => Some(r"(?-u:\b)"),
                    AssertionKind::NotWordBoundary => Some(r"(?-u:\B)"),
                    AssertionKind::StartLine | AssertionKind::EndLine => None,
                    _ => {
                        self.unobserved = true;
                        None
                    }
                };
                if let Some(replacement) = replacement {
                    self.edit(&assertion.span, replacement.to_owned());
                }
            }
            Ast::ClassPerl(class) => {
                self.ungreedy.sensitive = true;
                self.unobserved |= self.insensitive();
                self.perl(class, false);
            }
            Ast::ClassUnicode(class) => {
                self.ungreedy.sensitive = true;
                self.unobserved |= self.insensitive()
                    || class.negated
                    || !matches!(&class.kind, ast::ClassUnicodeKind::OneLetter('L'))
                        && !matches!(&class.kind, ast::ClassUnicodeKind::Named(name) if name == "Nd");
            }
            Ast::ClassBracketed(_) => {
                self.ungreedy.sensitive = true;
                self.unobserved |= self.insensitive();
            }
            Ast::Dot(_) => self.ungreedy.sensitive = true,
            Ast::Repetition(rep) => {
                self.unobserved |= matches!(rep.op.kind, ast::RepetitionKind::Range(_));
                self.ungreedy.sensitive |= !rep.greedy || !matches!(*rep.ast, Ast::Literal(_));
            }
            _ => {}
        }
        Ok(())
    }

    fn visit_post(&mut self, node: &Ast) -> Result<(), Self::Err> {
        if matches!(node, Ast::Group(_)) {
            self.flags.pop();
        }
        Ok(())
    }

    fn visit_class_set_item_pre(&mut self, item: &ast::ClassSetItem) -> Result<(), Self::Err> {
        match item {
            ast::ClassSetItem::Literal(literal) => {
                self.unobserved |= !literal_allowed(literal);
                if self.insensitive() && literal.c.is_ascii_alphabetic() {
                    self.edit(
                        &literal.span,
                        format!(
                            "{}{}",
                            &self.pattern[literal.span.start.offset..literal.span.end.offset],
                            counterparts(literal.c, literal.c)
                        ),
                    );
                }
            }
            ast::ClassSetItem::Range(range) => {
                self.unobserved |= !literal_allowed(&range.start) || !literal_allowed(&range.end);
                if self.insensitive() {
                    self.edit(
                        &range.span,
                        format!(
                            "{}{}",
                            &self.pattern[range.span.start.offset..range.span.end.offset],
                            counterparts(range.start.c, range.end.c)
                        ),
                    );
                }
            }
            ast::ClassSetItem::Perl(class) => self.perl(class, true),
            ast::ClassSetItem::Ascii(_) => self.refused = true,
            ast::ClassSetItem::Union(_) => {}
            _ => self.unobserved = true,
        }
        Ok(())
    }

    fn visit_class_set_binary_op_pre(
        &mut self,
        _: &ast::ClassSetBinaryOp,
    ) -> Result<(), Self::Err> {
        self.unobserved = true;
        Ok(())
    }
}

pub(super) fn analyze(pattern: &str, mode: Unrecorded) -> Result<Analysis, RegexError> {
    let tree = ast::parse::ParserBuilder::new()
        .build()
        .parse(pattern)
        .map_err(|error| {
            use ast::ErrorKind;
            match error.kind() {
                ErrorKind::NestLimitExceeded(_) => RegexError::ResourceLimit,
                ErrorKind::GroupUnclosed
                | ErrorKind::GroupUnopened
                | ErrorKind::ClassUnclosed
                | ErrorKind::EscapeUnexpectedEof
                | ErrorKind::RepetitionMissing => RegexError::InvalidSyntax,
                _ if mode == Unrecorded::Refuse => RegexError::Unobserved,
                _ => RegexError::InvalidSyntax,
            }
        })?;
    let mut walker = ast::visit(
        &tree,
        Walker {
            pattern,
            edits: Vec::new(),
            flags: vec![false],
            capture_groups: 0,
            refused: false,
            unobserved: false,
            ungreedy: Ungreedy::default(),
        },
    )?;
    if walker.refused {
        return Err(RegexError::InvalidSyntax);
    }
    if mode == Unrecorded::Refuse
        && (walker.unobserved || walker.ungreedy.flag_present && walker.ungreedy.sensitive)
    {
        return Err(RegexError::Unobserved);
    }
    walker.edits.sort_by_key(|edit| edit.0);
    let mut result = pattern.to_owned();
    for (start, end, replacement) in walker.edits.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    Ok(Analysis {
        pattern: result,
        capture_groups: walker.capture_groups,
    })
}
