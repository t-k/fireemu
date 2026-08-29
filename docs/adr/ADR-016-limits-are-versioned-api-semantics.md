# ADR-016: Limits are versioned API semantics

- Status: accepted (2026-08-29)

## Decision

Limit values are declared in immutable, dated catalogs under `spec/limits/` with their official
source, unit, inclusive / exclusive boundary, enforcement stage and implementation status. A
generator renders them into checked-in Rust constants; runtime code never embeds a limit
literal. When an official document changes, a new catalog ID is added and the old one is kept
for reproducibility. `cargo run -p limit-catalog-gen -- check` fails CI on drift.
