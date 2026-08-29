# ADR-033: Mutant IDs and Loom scenario names have one source of truth

- Status: accepted (2026-08-29)

## Decision

`verification/mutants/catalog.json` (spec 27.5) and `verification/loom/scenarios.json`
(spec 23.3) are the only places that define semantic mutant IDs and Loom scenario names.
`verification/requirements/requirements.json` references them; `tools/traceability-check`
fails CI on duplicates, undefined references, critical mutants not referenced by any requirement,
and implemented critical requirements lacking a formal artifact, a dynamic test or a mutation.
