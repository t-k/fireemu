//! Loaded ruleset shared between adapters (hot-reloadable through the control API).

use crate::ast::Ruleset;
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
    pub fn from_source(source: &str) -> Result<Self, ParseError> {
        let ruleset = parse_ruleset(source)?;
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
