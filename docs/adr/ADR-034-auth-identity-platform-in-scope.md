# ADR-034: Firebase Auth / Identity Platform (including TOTP MFA) is in scope

- Status: accepted (2026-08-30)

## Decision

Firebase Auth / Identity Platform is a compatibility area of firebase-testd, not a non-goal.
Native Security Rules evaluation needs an authoritative source for `request.auth` and
`request.auth.token`; without an Auth core the `RULES-1` capability cannot be demonstrated.
The TOTP second factor, which the official Auth Emulator does not offer, is part of the first
version because the virtual clock makes RFC 6238 boundaries (time step edges, window, replay
rejection, enrollment expiry) testable without sleeping.

## Consequences

- `ftd-core-auth` stays std-only: SHA-1, HMAC-SHA1 and base32 are implemented in-crate with
  RFC test vectors. Token signing is an adapter concern.
- Shared secrets are wrapped in `TotpSecret`, redacted in `Debug`, and never written to canonical
  traces or default snapshots (`INV-AUTH-003`).
- Unpublished backend parameters (window width, enrollment session lifetime) are versioned
  policies and conformance items, never claimed as exact.
- The official Auth Emulator is classified `OFFICIAL_EMULATOR_DIVERGENCE` for TOTP; real-service
  conformance requires Identity Platform and is opt-in.
