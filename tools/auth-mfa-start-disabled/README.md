# mfaSignIn:start on a disabled account (AUTH-U03)

One production flow answers a single AUTH-U03 question: after an account with a valid MFA pending credential is disabled administratively, what does an otherwise well-formed `mfaSignIn:start` return, and does the same pending credential work once the account is re-enabled? A disabled account cannot sign in with a password to obtain a pending credential, so the credential is obtained while the account is enabled, then the account is disabled.

The oracle project has MFA disabled, no phone sign-in and an empty SMS region allowlist, so the recorder reuses the configuration change, PATCH transport, restore and recovery of `tools/auth-pending-revocation`: phone MFA, one test phone number with a fixed code and the default SMS region policy are enabled for the run and restored in `finally`, with the restore readback and whole-configuration digest comparison part of the report. SIGTERM and SIGHUP unwind through the same `finally`, and a production run refuses to start from a checkout with uncommitted changes in any probe tree.

Rows, in order:

| Row | Basis | What is sent |
| --- | --- | --- |
| `baseline-fresh-finalize` | control | A fresh pending credential completes the phone second factor while enabled. |
| `disabled-start` | diagnostic | The account is disabled and read back; the pending credential obtained before the disable is presented to `mfaSignIn:start`. Accepted and refused are both valid observations; `USER_DISABLED` is not pinned as the answer. |
| `disabled-finalize` | diagnostic | If the disabled start returned a session, that session is finalized; skipped otherwise. |
| `reenabled-start` | diagnostic | The account is re-enabled and read back; the same pending credential is presented to `mfaSignIn:start`, showing whether the disabled attempt consumed it. |
| `reenabled-finalize` | diagnostic | If the re-enabled start returned a session, it is finalized. |
| `final-fresh-finalize` | control | A fresh sign-in completes the second factor after the run. |

A diagnostic row records any refusal, including an unlisted class, a throttle or a server error, and the run continues; such a run is not complete, so the receipt cannot be published until the class is named in the contract or the run is repeated. Only the two fresh finalizes are controls that must fully succeed. The pending credential is confirmed obtained before the disable (`heldPendingBeforeDisable`). Pending credentials, session identifiers, codes, tokens and passwords stay in memory; an aborted run keeps only the last request's step (named before the request), its status, error class and an allowlisted diagnostic code, plus the failure's exception class. Raw error text is never written. The account is deleted with UID and email absence confirmation.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-mfa-start-disabled -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-mfa-start-disabled/start_disabled_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-mfa-start-disabled/start_disabled_recorder.py --production --recover /absolute/private/run/account/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-mfa-start-disabled/start_disabled_recorder.py --production --restore-config /absolute/private/run/config-recovery.json
```

## Local run of the same corpus

`start_disabled_owned.py` builds and owns the strict fireemu artifact and runs the same `observe()` against it with no configuration change and codes read from the emulator inspection route. On 2026-09-12 the owned local run refused `mfaSignIn:start` on the disabled account with `USER_DISABLED`, skipped the disabled finalize, and the same held pending credential started and finalized after re-enablement; this is the local behavior, not evidence of production. The production run, its publication, comparison and approval are separate steps.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-mfa-start-disabled/start_disabled_owned.py --output /absolute/private/new-local
```
