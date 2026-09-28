# beforeSignIn blocking function that disables the account

One production flow deploys a first-generation `beforeSignIn` blocking function for the run, observes what Identity Platform does when the function answers `{disabled: true}`, and removes the function again. Three dedicated accounts: A has a phone factor and the disabling custom claim, B has a phone factor and is the unaffected control, C has no second factor and the disabling claim. The function disables only accounts carrying the claim `fireemuDisableOnSignIn`; every other sign-in in the project passes through unchanged. The oracle project's MFA, phone sign-in with test numbers and SMS region policy are enabled for the run as in the pending-revocation recorder, and the trigger registration is restored with them.

The recorder checks its preconditions before anything is written or deployed, saves a private recovery record (the configuration read, the function name and region) immediately before the first change, deploys from a private copy of the checked-in function source, reads the trigger registration back, and in `finally` deletes the accounts with absence confirmation, deletes the function with absence in the listing as the authority, restores the configuration from the values read and compares the whole-configuration digest. `--restore` replays the removal and restore from the recovery record after an interrupted run. Tokens, codes and passwords stay in memory; an aborted run keeps only the failing step, HTTP status and error class.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-disable/blocking_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-disable/blocking_recorder.py --production --restore /absolute/private/run/hook-recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-disable/blocking_recorder.py --production --recover /absolute/private/run/a/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-blocking-disable -q
```

## Observed on 2026-09-11 (recorded with the recorder at `08002f5`; published as an unapproved candidate)

With the function registered, B's phone MFA completions succeeded before and after the hook observations. C's password sign-in was refused with `USER_DISABLED` and no tokens were returned; the Admin readback immediately afterwards showed `disabled: false`, and a second sign-in was refused with `USER_DISABLED` again. A's phone MFA finalize was refused with `USER_DISABLED` and no tokens were returned; the Admin readback showed `disabled: true`, and a second sign-in was refused with `USER_DISABLED`. Both accounts were deleted, the function was removed, and the configuration was restored with a matching digest.

So production refuses the same request in which the blocking function disables the account, for a first-factor sign-in and for an MFA finalize alike. Whether the disable persists on the record differed between the two accounts in this single run (not persisted at the immediate readback for C, persisted for A); the run did not wait or read back again, so no propagation claim follows. This differs from fireemu, which applied the hook response and still issued tokens on the same request; see the fix recorded in `tools/auth-pending-retry/README.md`.

Earlier attempts in the same session: the second-generation identity handler of firebase-functions 6 rejected the blocking token's audience (Identity Platform registers and signs for the cloudfunctions.net URI, the handler expects run.app), so the function uses the first-generation API; and the readback row originally required the flag to be persisted, which would have failed the run on an observation rather than recording it.

This covers one function shape (a disabling response for a claim), one run, phone MFA with test numbers, no tenant, and neither a rejecting function nor `beforeCreate`. Refused rows record the HTTP status and the classified error only; the absence of tokens in a refused response is not an independent check of this recorder, and the persisted flag was read back once immediately (false for C, true for A), so the recorded observation supports "the same request is refused" and not "the disable is persisted immediately on every path". Any human approval is a separate step and should be worded to that record.

After the run the recorder was hardened without re-running it: a raw API response is no longer bound to a row while its follow-up requests run (an interrupted follow-up could have saved it to the private report), an account whose creation response was lost is no longer reported absent (it is recovered by email or stays unconfirmed with its journal), and the MFA account's second sign-in accepts a pending credential as a valid observation. Safety tests drive `observe()` against a scripted fake and reproduce each of the three against the previous behavior.

## Local run of the same corpus

`blocking_owned.py` builds the strict fireemu artifact, starts it with `--only auth,functions` and the local fixture in `function-local` (the second-generation identity API at the SDK version fireemu's runner supports, installed into a private copy), points the Functions runtime at the repository's `tools/runner-node/index.mjs`, and runs the same `observe()` against it: no deployment, no configuration change, and codes read from the emulator inspection route instead of test phone numbers. On 2026-09-12 the local run matched the production record on every row except `hook-c-disabled-readback`, which reads true locally and read false in production; that difference is the open gap GAP-AUTH-001. The local report is private; a comparison record against the approved production receipt is published separately.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-disable/blocking_owned.py --output /absolute/private/new-local
```
