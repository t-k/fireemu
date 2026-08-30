# ADR-034: Firebase Auth / Identity Platform (including TOTP MFA) is in scope

- Status: accepted (2026-08-30)

## Decision

Firebase Auth / Identity Platform is a compatibility area of fireemu, not a non-goal.
Native Security Rules evaluation needs an authoritative source for `request.auth` and
`request.auth.token`; without an Auth core the `RULES-1` capability cannot be demonstrated.
The TOTP second factor, which the official Auth Emulator does not offer, is part of the first
version because the virtual clock makes RFC 6238 boundaries (time step edges, window, replay
rejection, enrollment expiry) testable without sleeping.

## Consequences

- `fireemu-core-auth` stays std-only: SHA-1, HMAC-SHA1 and base32 are implemented in-crate with
  RFC test vectors. Token signing is an adapter concern.
- Shared secrets are wrapped in `TotpSecret`, redacted in `Debug`, and never written to canonical
  traces or default snapshots (`INV-AUTH-003`).
- Unpublished backend parameters (window width, enrollment session lifetime) are versioned
  policies and conformance items, never claimed as exact.
- The official Auth Emulator is classified `OFFICIAL_EMULATOR_DIVERGENCE` for TOTP; real-service
  conformance requires Identity Platform and is opt-in.

## Amendment (2026-08-31): the default snapshot policy for TOTP secrets

`INV-AUTH-003` says shared secrets are never written to default snapshots. The Auth snapshot
hook now captures an `AuthSnapshot` rather than a copy of the store:

- Enrolled TOTP factors are captured with a *detached* secret (an empty buffer): the
  enrollment id, display name, enrollment time and replay boundary are kept, the secret is not.
- Pending TOTP enrollments are not captured at all; a restore lands on a store where the
  enrollment session is unknown, which is what a client sees after the session expires.
- On restore each detached factor is rebound to the secret the live store still holds for the
  same user and enrollment id, and the replay boundary keeps the higher of the two accepted
  steps (`INV-AUTH-001`). A factor whose secret is gone by then (withdrawn, the account
  deleted, or the session reset since the capture) is dropped from the restored account and
  counted in a `RestoreReport`, which the daemon prints to stderr. A factor is never restored
  with a secret that verifies nothing, and a restore that dropped factors is never claimed
  faithful.
- `TotpSecret` zeroes its buffer when dropped (an ordinary write the crate keeps with
  `black_box`; the crate forbids `unsafe`), and a detached secret never matches a code.

There is no sensitive snapshot mode: a snapshot that would carry secrets is not offered.
