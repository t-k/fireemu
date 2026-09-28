# Credential and MFA collector integrity

## Scope

These changes affect the Python observation helpers and the local MFA recovery driver,
not the Auth service implementation. They do not authorize a production run, validate
an RSA signature, or complete AUTH-CREDENTIAL / AUTH-MFA / any parent acceptance gate.
Existing historical receipts stay immutable. A changed module digest requires a new
actual artifact run before claiming that the current recorder produced an observation.

## Credential shape extraction

`auth-credential-tokens/credential_collector.py` uses one compact-JWT parser for
`claim_shape` and `subjects_match`. Header, payload and signature encoding must have the
compact base64url shape. The JSON-bearing segments must be UTF-8 objects with unique
keys at every level and finite numbers. An unsigned `alg=none` envelope has an empty
signature; a declared signed envelope has a nonempty base64url signature.

This is **not cryptographic verification**: a syntactically shaped RS256 envelope with
invalid signature bytes is still described as `trustRoot: signed`. A positive subject
comparison only compares two parsed `sub` values; it does not establish common issuer,
tenant, account authorization, expiry, or token authenticity. Service/SDK verification
and the collector's independently recorded assertions remain separate obligations.

The `times` projection contains only strict integer values, never booleans. Fractional
numbers and other values remain visible in `claimTypes` instead of being coerced into
whole seconds. This collector's projection is not a claim that general JWT NumericDate
values cannot be fractional. No validity/expiry decision is made by this projection.

The 256 KiB compact-token and 128-container-depth limits are defensive local parser
limits, not Identity Platform quotas. Error messages do not include offending JWT keys,
raw token strings, or parser excerpts. The owned-account cleanup helper accepts actual
boolean readback flags only and rechecks their types when constructing its summary.

References: RFC 7515, section 2 and appendix C,
<https://www.rfc-editor.org/rfc/rfc7515.html>; RFC 7519, sections 2 and 4,
<https://www.rfc-editor.org/rfc/rfc7519.html>. RFC 7519 allows duplicate claims to be
rejected **or** handled by a last-member parser. This diagnostic collector deliberately
chooses rejection to avoid inconsistent evidence interpretation; last-member parsing
by itself is not described here as a blanket RFC violation.

## MFA state transitions

`auth-totp-enroll/mfa_collector.py` validates the complete case denominator, order,
state-field shapes, nonnegative typed request counts, finite times, typed cleanup flags,
and abort/reason consistency when writing/loading a checkpoint or judging run completion.
An empty or duplicated step list cannot become a complete run merely by recomputing its
self-hash. The 2 MiB checkpoint limit is a local bound, not a service quota.

`record_step` validates every dependency before committing changes. An unknown dependent,
invalid time/charge or schedule that overwrites a resolved/already scheduled dependency
leaves the state unchanged. Accepted observations are deep-copied so caller mutation does
not alter historical observations. A due-time step cannot be recorded early. A response
received after the wall deadline remains recorded and charged but latches an abort;
cleanup completing later does not remove that abort. Zero-cost local observations remain
representable; this library never sends requests and is not a substitute for charging
actual transport traffic. The local shadow retains the `Instance.requests` counter.

An exhausted request allowance cannot dispatch another pending observation. Invalid
clock input latches an abort; this finite check is not a persistent trusted-clock or
reboot/clock-rollback guarantee. The caller's transport must still enforce its own bounds.

`load_checkpoint(data, plan=independently_held_plan)` also checks the manifest digest,
nonce digest, request ceiling and deadline. The local shadow uses this form. Loading
without `plan` checks structure and integrity only. Neither a self-hash nor optional plan
binding authenticates the producer, proves current resource state, supplies cleanup
permission, or makes the old checkpoint safe to replay against a live service.

## MFA cleanup

`_delete_owned` attempts only distinct UIDs registered in the in-process state and supplied
by the current local run. Each UID receives at most one delete and, on an acknowledged
delete, one final lookup. A delete must be a typed 200 with an empty response or the known
DeleteAccountResponse kind. Final absence must be a typed 200 with the known
GetAccountInfoResponse kind or explicit empty users, without contradictory/unknown
fields. Arbitrary `{}`, `users: null`, error/success mixtures and paged responses are not
absence evidence. A failed current attempt clears stale in-memory cleanup flags.

Ordinary per-account transport failures leave that UID outstanding and do not prevent
cleanup of the remaining confirmed accounts. Interrupted cleanup (BaseException), the
process dying, failure before registering a created UID, raw HTTP parser/timeout limits,
persistence failures and restart authorization remain separate boundaries; this is not
a new automatic orphan-recovery capability. The ordinary failure path in `run_sequence`
still saves the checkpoint after cleanup and records the actual instance request count.

## Validation and remaining work

The new Python tests use the real helpers and sequence/finally code with artificial
Identity responses. Existing targeted credential and MFA tests must pass alongside them.
The negative controls run these tests against the unmodified v17 modules, excluding only
five tests for the newly added expected-plan keyword API. Additional selected mutation
checks are finite regression evidence, not an independent security review.

No native build, real Firebase SDK, MFA SMS/TOTP runtime, production token verifier,
new artifact shadow or production observation is established by these tests. Re-run the
repository's locked Python/native/SDK lanes, create new source/artifact-bound evidence,
and perform independent review before closing the parent acceptance groups.
