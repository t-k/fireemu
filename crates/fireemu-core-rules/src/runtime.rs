//! Loaded ruleset shared between adapters (hot-reloadable through the control API).

use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};

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

#[derive(Debug)]
struct ActiveRules {
    generation: u64,
    loaded: Arc<LoadedRules>,
}

/// One immutable ruleset generation retained by an admitted evaluation.
#[derive(Clone, Debug)]
pub struct RulesetSnapshot(Arc<ActiveRules>);

impl RulesetSnapshot {
    /// Monotonic generation assigned at atomic publication.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.0.generation
    }

    /// The immutable loaded rules and generation-local diagnostics.
    #[must_use]
    pub fn loaded(&self) -> Arc<LoadedRules> {
        Arc::clone(&self.0.loaded)
    }
}

impl Deref for RulesetSnapshot {
    type Target = LoadedRules;

    fn deref(&self) -> &Self::Target {
        &self.0.loaded
    }
}

/// Atomically published rulesets with immutable request snapshots.
#[derive(Debug)]
pub struct RulesetSlot {
    active: RwLock<Arc<ActiveRules>>,
}

impl RulesetSlot {
    /// Creates generation zero from the initial loaded rules.
    #[must_use]
    pub fn new(loaded: LoadedRules) -> Self {
        Self {
            active: RwLock::new(Arc::new(ActiveRules {
                generation: 0,
                loaded: Arc::new(loaded),
            })),
        }
    }

    /// Captures one immutable generation for a complete logical evaluation.
    pub fn snapshot(&self) -> Result<RulesetSnapshot, String> {
        self.active
            .read()
            .map(|active| RulesetSnapshot(Arc::clone(&active)))
            .map_err(|_| "ruleset slot is poisoned".to_owned())
    }

    /// Publishes a fully checked candidate and returns its fresh generation.
    pub fn replace_loaded(&self, loaded: LoadedRules) -> Result<u64, String> {
        let mut active = self
            .active
            .write()
            .map_err(|_| "ruleset slot is poisoned".to_owned())?;
        let generation = active
            .generation
            .checked_add(1)
            .ok_or_else(|| "ruleset generation is exhausted".to_owned())?;
        *active = Arc::new(ActiveRules {
            generation,
            loaded: Arc::new(loaded),
        });
        Ok(generation)
    }

    /// Checks a source completely before publishing it.
    pub fn replace_source(&self, source: &str) -> Result<u64, String> {
        let loaded = LoadedRules::from_source(source).map_err(|error| error.to_string())?;
        self.replace_loaded(loaded)
    }

    /// Publishes an empty rules generation.
    pub fn clear(&self) -> Result<u64, String> {
        self.replace_loaded(LoadedRules::default())
    }
}

impl Default for RulesetSlot {
    fn default() -> Self {
        Self::new(LoadedRules::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{LoadedRules, RulesetSlot};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Arc;

    const V1: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
    const V2: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

    #[test]
    fn generation_exhaustion_preserves_the_active_arc() {
        let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
        {
            let mut active = slot.active.write().unwrap();
            *active = Arc::new(super::ActiveRules {
                generation: u64::MAX,
                loaded: active.loaded.clone(),
            });
        }
        let before = slot.snapshot().unwrap();

        let error = slot
            .replace_source(V2)
            .expect_err("generation must be exhausted");

        assert!(error.contains("exhausted"));
        let after = slot.snapshot().unwrap();
        assert_eq!(after.generation(), u64::MAX);
        assert_eq!(after.source.as_deref(), Some(V1));
        assert!(Arc::ptr_eq(&before.0, &after.0));
    }

    #[test]
    fn poisoned_slot_refuses_reads_and_publications() {
        let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
        let retained = slot.snapshot().unwrap();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = slot.active.write().unwrap();
            panic!("poison ruleset slot for fail-closed coverage");
        }));
        assert!(poisoned.is_err());

        assert!(slot.snapshot().is_err());
        assert!(slot.replace_source(V2).is_err());
        assert_eq!(retained.source.as_deref(), Some(V1));
        assert_eq!(retained.generation(), 0);
    }
}
