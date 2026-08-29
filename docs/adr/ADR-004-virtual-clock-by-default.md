# ADR-004: Virtual clock by default

- Status: accepted (2026-08-29)

## Decision

The runtime never calls `SystemTime::now()`. Every session owns a `VirtualClock`; the
`deterministic` profile advances it only through explicit `set` / `advance` / `advanceTo` /
`runDue` commands. Moving the clock backwards requires an explicit call that is counted and
traced (`set_allow_backwards`). Fixture loaders tick the clock by one nanosecond per document
so that create-time ties only occur when a test asks for them (INV-TIME-001).
