# Precedence of overlapping refusals (AUTH-U03, revision 1)

One production flow observes which refusal wins when two apply to the same request: an account disabled while it holds an MFA pending credential and an open SMS session, finalized with a wrong code (target A) and with the correct code (control-by-contrast B), and a client `accounts:update` whose ID token has a tampered signature and which also carries an administrator-only field. Which error class comes back, and whether the refusal consumed the held credential and session, are the observations. No row encodes the local order recorded in `tools/auth-pending-retry/README.md`.

The oracle project has no MFA, no phone sign-in and an empty SMS region allowlist, so the recorder reuses the configuration change, PATCH transport, restore and recovery of `tools/auth-pending-revocation`: phone MFA, two test phone numbers with a fixed code and the default SMS region policy are enabled for the run, the configuration read before the change is saved to a private `config-recovery.json` immediately before the change is attempted, nothing is written when the preconditions fail, the recorded values are restored in `finally` from what was read, and the restore readback plus the whole-configuration digest comparison are part of the report. Test phone numbers never send SMS.

Both accounts are created with private recovery journals, verified UIDs, a verified email and an administrative phone factor enrollment, exactly as in the pending-revocation setup that production accepted. The rows, in order:

| Row | Kind | What is sent |
| --- | --- | --- |
| `baseline-a-fresh-finalize`, `baseline-b-fresh-finalize` | control | Fresh pending credential, start, finalize with the test code; tokens checked on their own claims and a derived lookup. |
| `invalid-token-admin-field-update` | diagnostic | Client `accounts:update` with A's baseline ID token whose signature has one character changed inside the signature, a sentinel custom claim in `customAttributes` (administrator-only) and a sentinel `photoUrl` (client-permitted). Sent before any disable so only an invalid signature and a privileged field overlap. The fields are chosen so that an unexpected acceptance cannot change A's verified email, factor enrollment, ownership marker or MFA eligibility. A privileged readback of A precedes and follows the request; an accepted row records whether each field was applied, and `invalidTokenStateUnchanged` projects whether custom claims, photo URL, display name and verified flag are as before. |
| (held) | harness | A and B each obtain a pending credential and start an SMS session; the code is captured now so later attempts reuse the same session. Both accounts are then disabled through privileged `accounts:update` and read back. |
| `disabled-a-wrong-code-finalize` | diagnostic | A's held credential and session with a fixed wrong six-digit code that differs from the test code in every position. |
| `disabled-b-correct-code-finalize` | diagnostic | B's held credential and session with the correct code. A and B differ only in the code, so the two rows show whether the code or the account state is checked first. |
| (re-enable) | harness | Both accounts are re-enabled and read back. |
| `reenabled-a-held-finalize`, `reenabled-b-held-finalize` | diagnostic | The same pending credential and session with the correct code, showing whether the earlier refusal consumed them. |
| `final-a-fresh-finalize`, `final-b-fresh-finalize` | control | Fresh pending credential, start, finalize, proving the environment still works after the run. |

Diagnostic rows accept either outcome and never abort the run: an accepted tampered-token update is recorded with whether each field was applied, and an accepted diagnostic finalize records every token check (presence, claims, second-factor claim, derived lookup) as a boolean, so tokens issued to a disabled account whose lookup is then refused are kept as an observation. Control rows must pass every check. Both accounts are deleted with UID and email absence confirmation. Pending credentials, session identifiers, codes, tokens (including the tampered one) and passwords stay in memory; an aborted run keeps only the step of the last request (named before the request is sent, so a transport failure leaves the step with no status), its HTTP status, error class and an allowlisted diagnostic code, plus the failure's exception class; cleanup requests after a failure do not overwrite them, and raw error text is never written. `--restore-config` restores from the private record after an interrupted run and `--recover` reconciles an account journal.

Not covered by revision 1: an expired pending credential with a code that is valid on its own (the production pending lifetime is not documented and would need a long wait; planned as a separate revision), refusals on `mfaSignIn:start` for a disabled account, TOTP, tenants and blocking functions.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-refusal-precedence -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-refusal-precedence/precedence_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-refusal-precedence/precedence_recorder.py --production --recover /absolute/private/run/a/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-refusal-precedence/precedence_recorder.py --production --restore-config /absolute/private/run/config-recovery.json
```

## Local run of the same corpus

`precedence_owned.py` builds and owns the strict fireemu artifact and runs the same `observe()` against it with no configuration change and codes read from the emulator inspection route. It validates the recorder end to end and records the local order; it is not evidence of production behavior.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-refusal-precedence/precedence_owned.py --output /absolute/private/new-local
```

The production run, its publication as a receipt and page, and any human approval are separate steps that each need their own decision.
