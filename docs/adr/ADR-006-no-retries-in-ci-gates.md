# ADR-006: CI gates never retry tests

- Status: accepted (2026-08-29)

## Decision

The `pr` and `ci` nextest profiles set `retries = 0`. A test that passes after a retry is a
flaky diagnosis, not a success, and mutation gates never retry either. The
`flaky-diagnose` profile may retry but is never used as a gate.
