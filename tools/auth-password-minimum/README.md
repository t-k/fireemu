# Minimum-six password update

An independent twelve-case candidate for changing a dedicated account from a strong random password to exactly six random URL-safe ASCII characters under the explicit schema 1 ENFORCE min-six/max-4096 policy. It proves original signin before update, rejects the original password after, uses the update ID token and refresh token with lookup, and signs in with the new password. Public inputShape checks lengths, ASCII and distinctness without retaining values or password digests.

This is a short-lived random-email test account, not a password-security recommendation. The account has no application data and is deleted immediately after the flow. Admin APIs are limited to exact-project configuration/ownership and dedicated-account cleanup. Verified UID is persisted/read back before mutation. Normal UID/email absence and owned-process exit/listener closure do not prove fault-injected recovery.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-minimum/minimum_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-minimum/minimum_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-minimum/minimum_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-minimum.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-minimum.py --check
AUTH_PASSWORD_MINIMUM_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password-minimum -q
```

Source snapshots keep their original hashes/dates. No prior evidence or approvals change. One accepted six-character sample does not prove every six-character combination, maximum-length, Unicode, null/empty, custom-policy, elapsed-expiry, revocation-timing, SDK/Rules or full Auth behavior. New evidence remains candidate until a separate human decision.
