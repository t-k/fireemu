# Deleted-account credential observations

This bounded candidate uses two dedicated accounts, six baseline route observations, end-user deletion of A, then six post-deletion observations. A's original signin ID and refresh tokens remain fixed. Password signin, ID-token lookup and refresh-derived lookup are distinct checks. B is the unaffected successful control. Only deleted-A routes may refuse, and all three must refuse for a publishable observation; their exact bounded errors are retained for comparison rather than assumed equal.

The recorder verifies the production project number and recorded configuration, persists ownership before mutation, uses A's own ID token for deletion, and checks UID/email absence separately. It never enumerates or bulk-deletes accounts. Remaining owned accounts are cleaned in finally, independently. Unknown creation outcomes retain private recovery journals and cannot be resolved solely by an empty lookup. Tokens/passwords are never published. Public records contain allowlisted booleans, expiry values, error categories, timing and execution metadata, not independently verifiable raw token responses.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-deleted/deleted_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-deleted/deleted_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-deleted/deleted_recorder.py --production --recover /absolute/private/run/a/recovery.json
AUTH_DELETED_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-deleted/test_deleted_owned.py -q
```

The owned runner binds OS-assigned port0, checks the actual artifact and control-token identity, and requires exit0 and closed listeners. Source section mappings are not newly hash-bound full-page reviews. The corpus does not cover all token series, exact propagation, account recreation, expired-token timing, SDK/checkRevoked, Rules, tenants or fault-injected recovery. No previous approval is inherited.
