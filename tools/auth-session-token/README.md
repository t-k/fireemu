# Bounded REST session-token diagnostics

This recorder extends the approved password-change flow without inheriting its approval. It observes two pre-existing REST signin credential sets (A and B) and fresh password-change response credentials. It does not assume all old tokens are rejected immediately, and it does not implement an SDK verifyIdToken/checkRevoked test.

## Fixed experiment

1. Create and independently identify one dedicated account. Persist its verified UID before mutation.
2. Sign in as A, wait at least two seconds, sign in as B and require different refresh-token bytes. These are credential sets, not proven physical devices.
3. Lookup with each fixed ID token and refresh each original refresh token twice. Use each returned ID token for lookup. Rotation is recorded, but never replaces the observed refresh input.
4. Wait at least three seconds after baseline issuance, then change the password using A's fixed ID token. Require the changed token's decoded iat to exceed all baseline issuance times. Decoding is not signature verification.
5. At target offsets 0, 10 and 30 seconds after receiving the change response, observe six lanes: A.ID lookup, A.refresh exchange, B.ID lookup, B.refresh exchange, changed.ID lookup and changed.refresh exchange. Every accepted exchange is followed by lookup using its returned ID token.
6. After the observation window, verify new-password signin/lookup, delete the dedicated account and confirm exact UID/email absence. A failed final signin does not substitute another token into its lookup lane.

The corpus contains 32 top-level records, including 18 scheduled lane records. Refresh-derived lookups are nested records, not hidden within exchange success. All token input bytes are held in immutable mappings and reused, not replaced with newly returned values.

## Timing and interpretation

No new primary or derived-lookup request starts at or after 45 seconds. Each record preserves startMs, primaryEndMs, optional followupStartMs/followupEndMs and total endMs. Starts over 2000ms late or completion beyond the window cannot become on-time observations. The fixed schedule does not extend until rejection occurs.

The request helper uses a five-second socket/processing budget and checks elapsed time while reading. This is not hard real-time cancellation of DNS or underlying blocking I/O. Timed-out/incomplete requests remain transport failures; in-flight workers drain before deletion. Cleanup has separate request timeouts and is still attempted on failure. Parent/child process shutdown is checked by the owned runner.

Outcomes are accepted, auth-rejected with a fixed error category, unexpected, transport-failure or not-sampled. Fresh controls must succeed before a paired comparison is considered interpretable. Same results are labelled only as observed agreement; differing results are not automatically a compatibility failure at an exact propagation time. No rejection in the window does not prove permanent validity or the status of an entire rotated session lineage.

## Safety and commands

Production is fixed to the authorized fireemu-35fe6 / 592603257417 project, no tenant. Existing email/privacy/hooks preflight and explicit client password policy checks apply. No project configuration is changed. Admin APIs establish ownership and cleanup only. Private journals are created before signup, and verified UID is persisted before mutation or recovery deletion. Unknown creation outcomes are never resolved from an empty email lookup alone.

Use new private output directories outside tracked paths:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-token/session_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-token/session_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-token/session_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-session-token.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-session-token.py --check
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-session-token -q
AUTH_SESSION_TOKEN_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-session-token -q
```

The public receipt excludes raw tokens, token digests, passwords, UID/email and raw responses. Numeric iat/auth_time/validSince values are advisory, unverified metadata. Token reuse and identity comparisons are recorder testimony, not independent reconstruction. Same-second boundaries, a no-password-change longitudinal control, SDK, Rules, actual expiry, MFA, token rotation lineage and fault-injected recovery are separate work.

Earlier evidence and approvals remain immutable. A diagnostic receipt is not an approved compatibility claim. If later observations justify fixed expectations, create a new revision and new evidence rather than reinterpreting this receipt.
