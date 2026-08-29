# ADR-007: No unsafe in project source

- Status: accepted (2026-08-29)

## Decision

The workspace sets `unsafe_code = "forbid"`. If a measurable need arises, `unsafe` is isolated
in a dedicated crate with an ADR, a safety argument, Miri regressions, a Kani harness and a
fuzz target.
