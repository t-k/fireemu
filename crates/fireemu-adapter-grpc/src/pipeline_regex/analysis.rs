//! Validation and rewrite of a pipeline regex pattern (stub: the tests are red).

use fireemu_core_firestore::pipeline_exec::{RegexError, Unrecorded};

pub(super) struct Analysis {
    pub(super) pattern: String,
    pub(super) capture_groups: usize,
}

pub(super) fn analyze(_pattern: &str, _mode: Unrecorded) -> Result<Analysis, RegexError> {
    unimplemented!()
}
