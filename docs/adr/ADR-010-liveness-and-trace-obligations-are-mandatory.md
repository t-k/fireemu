# ADR-010: Safety alone is not enough; liveness and trace obligations are mandatory

- Status: accepted (2026-08-29)

## Decision

Behaviour-removing faults (event enqueue deleted, retry deleted, due schedule deleted) shrink the
reachable state set and cannot violate a safety invariant. Every important effect therefore
carries at least one of: a Quint liveness property, an observable trace obligation, a scenario
postcondition, or observational equivalence with a reference model. The Quint models under
`verification/quint/specs` check liveness (`LIVE-*`) alongside safety (`INV-*`), and generated Quint Connect traces compare the model with production state machines. Semantic model mutants must be caught by the configured checker before a model is accepted.
