# Blocking function that disables the account on the request that creates it

One flow deploys a first-generation `beforeSignIn` function for the production run that answers `disabled: true` when, and only when, the signing-in email's local part starts with a dedicated prefix. Target T signs up with that prefix, so the request that creates the account is the request the function disables; control C signs up with a random local part. The rows record whether T's sign-up is accepted or refused, whether tokens were returned (and, if so, whether they serve lookup and refresh), whether a record for T exists afterwards and is disabled, what T's own sign-in and a second sign-up with the same email do, and that C signs up, signs in and whether its photo URL is persisted. Only the blocking trigger is deployed; no MFA, phone or SMS configuration is touched, and the trigger registration is restored with a digest comparison.

The recorder follows `tools/auth-blocking-disable`: preconditions before any write, a private recovery record before the deployment, sanitized diagnostics, raw responses never bound to the report. T's cleanup is reported as deletion with absence confirmation when a record exists, and only when the creating request was answered with a refusal and no record was read back as `recordNeverCreated` with the email re-read as absent; an unanswered creation is never reported absent. The offline safety tests drive `observe()` against a scripted fake for both production shapes.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-create-disable/create_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-create-disable/create_recorder.py --production --restore /absolute/private/run/hook-recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-blocking-create-disable/create_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-blocking-create-disable -q
```

## Production observation (2026-09-11)

The production observation is complete. T's sign-up was refused with `USER_DISABLED`; token lookup and refresh were skipped because no tokens were returned; an Admin readback found T's disabled record; T's sign-in was refused with `USER_DISABLED`; and a second sign-up with the same email was refused with `EMAIL_EXISTS`. C's sign-up and both sign-ins were accepted. C's record existed and was not disabled, but its sign-up `photoUrl` was not persisted. The function was removed, the trigger registration and Auth configuration were restored with a matching digest, and both accounts were deleted with UID and email absence confirmation.

This is a candidate record of ten redacted production REST observations, not an approval. It does not contain raw token responses or independently verify token signatures or expiry. It covers one project, one first-generation `beforeSignIn` function, one run and no local artifact comparison; it does not establish behavior for other blocking events, tenants, MFA, phone or SMS flows, SDKs, Rules, or general Auth compatibility. The elapsed times are recorder measurements, not request or hook latency.

## Local run (2026-09-12)

The owned local artifact refused T's sign-up with `USER_DISABLED`, kept a disabled record for T (a second sign-up with the same email is `EMAIL_EXISTS`), and did not persist C's sign-up photo URL. `accounts:signUp` intentionally ignores the documented `photoUrl` field because the production observation showed that it is not persisted and is unavailable to the blocking hook on the creating request. The offline safety tests drive `observe()` against scripted fakes for both production response shapes.
