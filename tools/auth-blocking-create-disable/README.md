# Blocking function that disables the account on the request that creates it

One flow deploys a first-generation `beforeSignIn` function for the run that answers `disabled: true` when, and only when, the signing-in user carries a dedicated selector photo URL. Target T signs up with that photo URL, so the request that creates the account is the request the function disables; control C signs up with a plain photo URL. The rows record whether T's sign-up is accepted or refused, whether tokens were returned (and, if so, whether they serve lookup and refresh), whether a record for T exists afterwards and is disabled, what T's own sign-in and a second sign-up with the same email do, and that C signs up, signs in and reads back its photo URL. Only the blocking trigger is deployed; no MFA, phone or SMS configuration is touched, and the trigger registration is restored with a digest comparison.

The recorder follows `tools/auth-blocking-disable`: preconditions before any write, a private recovery record before the deployment, sanitized diagnostics, raw responses never bound to the report. T's cleanup is reported as deletion with absence confirmation when a record exists, and only when the creating request was answered with a refusal and no record was read back as `recordNeverCreated` with the email re-read as absent; an unanswered creation is never reported absent. The offline safety tests drive `observe()` against a scripted fake for both production shapes.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-create-disable/create_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-create-disable/create_recorder.py --production --restore /absolute/private/run/hook-recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-create-disable/create_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-blocking-create-disable -q
```

## Local run (2026-09-12)

The owned local artifact refused T's sign-up with `USER_DISABLED`, kept a disabled record for T (a second sign-up with the same email is `EMAIL_EXISTS`), and persisted C's sign-up photo URL. That last point needed a fix: fireemu's `accounts:signUp` ignored the documented `photoUrl` field, which also meant a hook could not select on it; sign-up now stores it before the hook runs. The production run has not been executed; its execution is a separate decision from this plan, and the production record will show whether a created-then-disabled account exists afterwards and whether sign-up persists `photoUrl`.
