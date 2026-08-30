//! Loaded ruleset shared between adapters (hot-reloadable through the control API).

use crate::ast::Ruleset;
use crate::lint::{lint_source, DiagnosticLevel, LintOptions};
use crate::parse::{parse_ruleset, ParseError};

/// The currently loaded rules: source text plus its parsed form. `None` means no rules are
/// configured; adapters then allow every request (the runtime prints a warning at start).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedRules {
    /// Source text as loaded.
    pub source: Option<String>,
    /// Parsed ruleset.
    pub ruleset: Option<Ruleset>,
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
        })
    }

    /// Whether rules are configured.
    #[must_use]
    pub const fn is_loaded(&self) -> bool {
        self.ruleset.is_some()
    }
}
