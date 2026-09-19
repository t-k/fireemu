# MFA pending credential across one revocation trigger (AUTH-U04)

One parameterized recorder observes whether an MFA pending credential and SMS session, held before a single account-state transition, still complete after it. Each trigger is an independent slice, production run, receipt and approval; none inherits the explicit-`validSince` approval of `auth-pending-revocation`, and the held rows are diagnostic (accepted or refused are both valid observations) while only the fresh finalizes are controls.

| Trigger (`--trigger`) | Transition observed |
| --- | --- |
| `client-password-change` | The account's own session `accounts:update` sets a new password. |
| `admin-password-update` | A privileged `accounts:update` sets a new password. |
| `password-reset` | An admin `sendOobCode PASSWORD_RESET` with `returnOobLink` yields a code, then `resetPassword` sets a new password. |
| `provider-unlink` | A federated identity linked administratively before the held credential is created is removed by the session `accounts:update deleteProvider`. |

The oracle project has MFA disabled, no phone sign-in and an empty SMS region allowlist, so the recorder reuses the configuration change, PATCH transport, restore and recovery of `auth-pending-revocation`: phone MFA, one test phone number with a fixed code and the default SMS region policy are enabled for the run, the configuration read before the change and its whole-configuration digest are saved to a private `config-recovery.json` immediately before the change, nothing is written when the preconditions fail, the recorded values are restored in `finally` (before the account is deleted), and the restore readback plus the digest comparison are part of the report. SIGTERM and SIGHUP unwind through the same `finally`, and a production run refuses to start from a checkout with uncommitted changes in any probe tree.

Common skeleton, per run:

1. Create the owned account (email/password), verify the email, enroll a phone factor. For `provider-unlink`, administratively link a federated identity and confirm it by readback; a refused link aborts the run as **unobservable** and is never recorded as an unlink result. The link precedes the held credential so it cannot itself affect it.
2. `baseline-fresh-finalize` (control): a fresh pending credential completes the second factor; its ID token is the session used by the self-service triggers.
3. Hold a pending credential and open an SMS session, capturing its code.
4. Snapshot the account, then fire exactly one trigger; the `trigger` row records the transition and a readback (for `provider-unlink`, that the provider is gone and nothing else changed; for the password triggers, that the account is still present and whether tokens were returned).
5. Present the held credential to `mfaSignIn:start` and `:finalize` on the session opened before the trigger; `held-lookup` and `held-refresh` run only when the held finalize is accepted.
6. `final-fresh-finalize` (control): a fresh sign-in with the current password completes the second factor.
7. Delete the account with UID and email absence confirmation.

A diagnostic row records any refusal, including an unlisted class, a throttle or a server error (`UNCLASSIFIED_ERROR` when unlisted), and the run continues; such a run is not complete, so the receipt cannot be published until the class is named in the contract or the run is repeated. Pending credentials, session identifiers, codes, tokens and passwords stay in memory; an aborted run keeps only the step of the last request (named before it is sent, so a transport failure leaves it with no status), its HTTP status, error class and an allowlisted diagnostic code, plus the failure's exception class. Raw error text is never written.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-pending-triggers -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-triggers/triggers_recorder.py --production --trigger <trigger> --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-triggers/triggers_recorder.py --production --trigger <trigger> --recover /absolute/private/run/account/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-triggers/triggers_recorder.py --production --trigger <trigger> --restore-config /absolute/private/run/config-recovery.json
```

## Local run of the same corpus

`triggers_owned.py --trigger <trigger>` builds and owns the strict fireemu artifact and runs the same `observe()` against it with no configuration change and codes read from the emulator inspection route. It validates the recorder end to end and records the local order; it is not evidence of production behavior. On 2026-09-12 all four triggers completed on an owned local artifact with the held credential surviving each (the production observation, per trigger, is what a run against the oracle answers).

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-triggers/triggers_owned.py --trigger <trigger> --output /absolute/private/new-local
```

Each production run, its publication as a receipt and page, and any human approval are separate steps that each need their own decision, one trigger at a time.

## Revision 2

Revision 2 records each token field of the transition response separately (`idTokenReturned`, `refreshTokenReturned`, `expiresInReturned`) instead of a single `tokensReturned`, so an unexpected refresh token or expiry is distinguished from a missing ID token (GAP-AUTH-004). A held row runs only when the accepted finalize actually returned the token it needs; a missing token skips the dependent row as unexecuted rather than synthesizing a refusal. A throttle or quota refusal is recorded but never completes a run, whatever its HTTP status. The receipt binds a broader dependency manifest (the trigger contract and recorder, the shared revocation and password-maximum recorders and contracts) to the recorder commit. Revision-1 observations are retained as history (`*-r1.md`).

The token-return checks are value-shape, not key presence: `idTokenReturned`, `refreshTokenReturned` and `expiresInReturned` are each true only when the field is a non-empty string. An absent key, an empty string, a null and a non-string value all read as false, so a receipt states that a field was not returned as a non-empty string, not that the key was absent (and `expiresIn: "garbage"` reads as returned). Splitting key presence from value shape is deferred to a future contract revision.
