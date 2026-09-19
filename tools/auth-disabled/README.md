# Account disable / re-enable observations

One flow uses two dedicated accounts: target A and unaffected control B. For each account, initial signin credentials are fixed in memory. Baseline, disabled and re-enabled phases separately exercise password signin, the original ID token via accounts:lookup, and the original refresh token followed by lookup with its derived ID token. Tokens returned during observation do not replace the fixed inputs.

Only A is mutated through privileged accounts:update. Its persisted UID and email ownership are rechecked before disable and re-enable, and Admin lookup confirms the flag and selected-field preservation. B must remain enabled and usable. Baseline and B routes must succeed, as must fresh signin after re-enable. Old A credentials after re-enable are diagnostic outcomes, not assumed restored. Timing is sequential and bounded: elapsed request-start milliseconds since each phase readback are recorded, not a promise of instantaneous revocation or stable long-term behavior.

Each account has an exclusive private recovery journal written before signup and a verified UID read back before mutation. Both accounts are deleted in finally, with UID/email absence confirmation; failed or unknown creation and cleanup cannot count as complete. Project configuration is read before/after and never changed. Tokens/passwords remain in memory and are excluded from public projections. An incomplete control, unclassified error or cleanup failure stops the run. The original sources and previous approvals remain untouched.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-disabled/disabled_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-disabled/disabled_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-disabled/disabled_recorder.py --production --recover /absolute/private/run/a/recovery.json
AUTH_DISABLED_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-disabled -q
```

Official references: [Admin user management](https://firebase.google.com/docs/auth/admin/manage-users), [session management](https://firebase.google.com/docs/auth/admin/manage-sessions), [REST routes](https://firebase.google.com/docs/reference/rest/auth), [privileged account update](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/update). These define operations and documented errors, not a universal timing or re-enable-token outcome. This flow does not cover SDK checkRevoked, Firestore Rules, actual token expiry, all sessions, tenant behavior, races or injected-failure recovery.
