# MFA pending credential across an explicit revocation

One production flow holds an MFA pending credential of target A across an explicit revocation and observes whether it can still complete, while unaffected control B and fresh sign-ins bound the run. The oracle project has no MFA, no phone sign-in and an empty SMS region allowlist, so the recorder enables phone MFA, two test phone numbers with a fixed code and the default SMS region policy for the run, waits for enforcement to follow the readback, and restores the recorded values in `finally`; the restore readback and the configuration digest comparison are part of the report. Test phone numbers never send SMS.

Both accounts are created with private recovery journals, verified UIDs and an administrative phone factor enrollment. Baseline rows complete a fresh pending credential for A and B. The held credential of A is then issued and never completed; two seconds later `validSince` is advanced through privileged `accounts:update` and read back, with B unchanged. The held credential is tried through `mfaSignIn:start` and `:finalize`; a returned ID token is compared on its own `auth_time` against `validSince`, used for `accounts:lookup`, and its refresh token is redeemed. Fresh sign-ins for A and B then complete. Only the held-credential rows are diagnostic: accepted and refused are both valid outcomes, and later held steps are skipped after a refusal. Both accounts are deleted with UID and email absence confirmation. Tokens, codes and passwords stay in memory; an aborted run keeps only the failing step, HTTP status and error class.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-revocation/revocation_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-revocation/revocation_recorder.py --production --recover /absolute/private/run/a/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-pending-revocation -q
```

## Observed on 2026-09-11 (private receipt, not yet published or approved)

The held credential was accepted: start and finalize returned 200 two seconds after the revocation, the ID token's `auth_time` was at or after `validSince`, lookup succeeded and the refresh token was redeemable. Baseline, fresh and control rows all succeeded, the configuration was restored with a matching digest, and cleanup confirmed absence. This matches the local behavior recorded in `tools/auth-pending-retry/README.md`, where finalization does not compare the pending credential's start time with `validSince`. Earlier attempts in the same session failed before any observation row on the SMS region policy (`OPERATION_NOT_ALLOWED`, region not enabled) and on enforcement lagging the configuration readback; both were resolved in the recorder without changing the observation design.

This covers explicit revocation only: no password change, no tenant, no blocking hook, phone MFA with test numbers, a two-second gap, and one run. It does not cover the pending credential's own expiry, SDK `checkRevoked`, or the precedence of overlapping refusals. Publication as a receipt and page, and any human approval, are separate steps.
