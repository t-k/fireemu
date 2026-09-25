# REST session-token observation revision 2

This independent revision repeats the fixed pre-change A/B ID and refresh credential experiment after a narrow runtime error-class correction. It adds `malformed-refresh` and `unknown-refresh`, using fixed deliberately invalid strings, to keep INVALID_REFRESH_TOKEN distinct from the TOKEN_EXPIRED response observed for known revoked sessions. These are two concrete input controls, not coverage of every malformed token. The corpus contains 34 top-level records; refresh-derived lookups remain nested and independently checked.

All original timing and safety limits remain: 0/10/30-second targets, a 45-second request-start deadline, immutable original credential bytes, distinct pre-change issuance, fresh-token controls, advisory unsigned JWT timing metadata, private ownership journal before account mutation, dual UID/email cleanup and owned process exit/listener checks. There is no retry-until-rejected rule and no assertion of universal immediate revocation. SDK checkRevoked, Rules, actual expiry, same-second production boundaries, explicit Admin revocation, password reset and deleted-account error parity remain separate scopes. Invalid controls are performed after the timed window and cannot change its sampling offsets.

Use new private output directories:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-v2/session_v2_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-v2/session_v2_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-session-v2/session_v2_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-session-v2.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-session-v2.py --check
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-session-v2 -q
```

Revision 1's diagnostic differences and all prior approvals remain immutable. Use `tools/compat-history/history.py --check` for their original artifact-bound checks. This revision produces a new unapproved candidate subject; prior approval never transfers to the patched artifact. Public receipts contain redacted observations, not raw tokens or independently reproducible token-signature evidence.
