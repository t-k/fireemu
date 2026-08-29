# ADR-017: Enforcement precision is published, never faked

- Status: accepted (2026-08-29)

## Decision

Every limit and feature carries an `EnforcementPrecision` (`exact`, `boundary-conformance`,
`conservative`, `estimated`, `oracle-only`, `not-applicable`, `unsupported`). An `estimated`
value is never the sole basis for a production-compatible hard error, and estimated values are
never displayed as exact (for example the Firebase compiled ruleset size).
