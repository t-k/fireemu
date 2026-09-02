//! Pure candidate ranking shared by Functions startup and formal conformance tests.

/// Production-derived facts used to rank one discovered Node installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeCandidate {
    /// Whether the loader supports synchronous `require()` of ES modules.
    pub require_module: bool,
    /// Whether the major version matches the configured Functions runtime.
    pub runtime_matches: bool,
    /// Whether the version satisfies `package.json`'s `engines.node` expression.
    pub engine_matches: bool,
}

/// Selects a discovered Node candidate with the production precedence rules.
///
/// An explicit `FIREEMU_NODE` selection is stable. Automatic discovery prefers loader
/// capability when requested, then the configured runtime major, then `engines.node`, and
/// finally discovery order.
#[must_use]
pub fn select_node_candidate(
    explicit: bool,
    prefer_require_module: bool,
    candidates: &[NodeCandidate],
) -> Option<usize> {
    if explicit {
        return (!candidates.is_empty()).then_some(0);
    }
    candidates
        .iter()
        .enumerate()
        .min_by_key(|(index, candidate)| {
            (
                prefer_require_module && !candidate.require_module,
                !candidate.runtime_matches,
                !candidate.engine_matches,
                *index,
            )
        })
        .map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::{select_node_candidate, NodeCandidate};

    #[test]
    fn precedence_is_capability_runtime_engine_then_order() {
        let candidates = [
            NodeCandidate {
                require_module: false,
                runtime_matches: true,
                engine_matches: true,
            },
            NodeCandidate {
                require_module: true,
                runtime_matches: false,
                engine_matches: false,
            },
            NodeCandidate {
                require_module: true,
                runtime_matches: true,
                engine_matches: false,
            },
            NodeCandidate {
                require_module: true,
                runtime_matches: true,
                engine_matches: true,
            },
        ];
        assert_eq!(select_node_candidate(false, true, &candidates), Some(3));
    }

    #[test]
    fn explicit_candidate_is_not_replaced_by_a_better_automatic_candidate() {
        let candidates = [
            NodeCandidate {
                require_module: false,
                runtime_matches: false,
                engine_matches: false,
            },
            NodeCandidate {
                require_module: true,
                runtime_matches: true,
                engine_matches: true,
            },
        ];
        assert_eq!(select_node_candidate(true, true, &candidates), Some(0));
    }
}
