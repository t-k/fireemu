# Administrative updates to a disabled account

One production flow disables owned target A through privileged `accounts:update` while control B stays enabled, then attempts an administrative password replacement and an administrative photo update on the disabled account. Whether the password update returns tokens is the observation; any returned tokens are tried for `accounts:lookup` and refresh. A's own sign-in with the new password is tried while disabled and after re-enablement, and B signs in at every phase. No project configuration is changed; the configuration is read before and after and must be unchanged.

The recorder mirrors `tools/auth-disabled`: private recovery journals, verified UIDs before every mutation, selected-state checks after the disable and re-enable transitions, deletion with UID and email absence confirmation. Raw API responses are never bound to the saved report; an aborted run keeps only the failing step, HTTP status and error class. Diagnostic rows (the two administrative updates, their token rows, A's sign-ins) accept either outcome; baseline and control rows must succeed. The offline safety tests drive `observe()` against a scripted fake for both production shapes (tokens returned or not) and for an interrupted follow-up.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-disabled-admin-update/admin_update_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-disabled-admin-update/admin_update_recorder.py --production --recover /absolute/private/run/a/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-disabled-admin-update -q
```

Local relevance: fireemu's administrative update issues tokens when credentials change unless the same request disables the account, so a password change on an already disabled account returns tokens locally (`docs.local` issue, gap ledger AUTH-U01). The production run has not been executed yet; execution is a separate decision from this plan.
