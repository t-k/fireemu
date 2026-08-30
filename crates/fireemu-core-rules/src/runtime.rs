//! Loaded ruleset shared between adapters (hot-reloadable through the control API).

use std::sync::{Arc, Mutex};

use crate::ast::Ruleset;
use crate::coverage::RulesDiagnostics;
use crate::lint::{lint_source, DiagnosticLevel, LintOptions};
use crate::parse::{parse_ruleset, ParseError};

/// The currently loaded rules: source text plus its parsed form. `None` means no rules are
/// configured; adapters then allow every request (the runtime prints a warning at start).
///
/// The diagnostics travel with the ruleset rather than beside it, because every position
/// they hold is an offset into *this* source. Replacing the slot therefore replaces the
/// coverage and the request traces too, which is the only correct behaviour and needs no
/// separate reset.
#[derive(Debug, Default)]
pub struct LoadedRules {
    /// Source text as loaded.
    pub source: Option<String>,
    /// Parsed ruleset.
    pub ruleset: Option<Ruleset>,
    /// Coverage and request traces recorded against this ruleset (`RULES-PARITY-04`).
    pub diagnostics: Arc<Mutex<RulesDiagnostics>>,
}

/// Two loaded rulesets are the same when they hold the same source and the same tree; what
/// has been observed about them is not part of their identity.
impl PartialEq for LoadedRules {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.ruleset == other.ruleset
    }
}

/// A clone is a separate ruleset -- a snapshot, or a copy handed to another surface -- and
/// starts with nothing observed, so a restored snapshot never inherits another run's
/// coverage.
impl Clone for LoadedRules {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            ruleset: self.ruleset.clone(),
            diagnostics: Arc::new(Mutex::new(RulesDiagnostics::default())),
        }
    }
}

impl LoadedRules {
    /// Parses `source` and returns the loaded rules.
    ///
    /// Two call-graph rules are compile errors rather than runtime ones, which is where the
    /// official compiler puts them: a recursive or cyclical call, and a call chain deeper
    /// than the catalog's maximum. Both were measured against the pinned emulator
    /// (`conformance/rules-programs.json`, `recursion-self-call` and
    /// `recursion-depth-chain-21-calls`), and the messages are its messages.
    pub fn from_source(source: &str) -> Result<Self, ParseError> {
        let ruleset = parse_ruleset(source)?;
        let report = lint_source(source, &LintOptions::default());
        for diagnostic in &report.diagnostics {
            if diagnostic.level != DiagnosticLevel::Error {
                continue;
            }
            let message = match diagnostic.limit_id {
                "RULES-RECURSION" => "Recursive call is not allowed.".to_owned(),
                "RULES-FUNCTION-CALL-DEPTH" => format!(
                    "Maximum allowed call depth of {} is reached for [{}]",
                    diagnostic.maximum,
                    diagnostic.subject.as_deref().unwrap_or("the call chain")
                ),
                _ => continue,
            };
            let span = diagnostic.span.unwrap_or_default();
            return Err(ParseError {
                message,
                line: span.line.max(1),
                column: span.column.max(1),
                offset: span.offset,
            });
        }
        Ok(Self {
            source: Some(source.to_owned()),
            ruleset: Some(ruleset),
            diagnostics: Arc::new(Mutex::new(RulesDiagnostics::default())),
        })
    }

    /// Whether rules are configured.
    #[must_use]
    pub const fn is_loaded(&self) -> bool {
        self.ruleset.is_some()
    }
}
