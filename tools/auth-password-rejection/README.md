# Weak-password rejection control

This independent 16-case candidate compares a five-character ASCII password update refusal under the recorded schema 1 ENFORCE minimum-six policy, followed by preserved original-password signin, fixed original ID/refresh token use and selected-state lookup. It ends with a distinct strong update and new-password signin, so rejecting all updates cannot satisfy the flow.

Original refresh bytes are used both before and after rejection. Returned refresh credentials never replace the observation input. Seven token-returning cases check positive-integer expiry and 3600 separately; successful token use does not prove elapsed expiry. The final valid-update refresh token is only presence-checked. Secret-free comparison preserves field absence/null and JSON types and excludes changing credential metadata.

Record only into new private directories:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-rejection/rejection_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-rejection/rejection_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-rejection/rejection_recorder.py --production --recover /absolute/private/new-production/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-rejection.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-rejection.py --check
AUTH_PASSWORD_REJECTION_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password-rejection -q
```

Production is fixed to fireemu-35fe6 / 592603257417, with auth/client-policy pre/post readback. Private exclusive-create journal and verified UID readback precede mutation; cleanup verifies UID/email ownership and absence independently of working passwords. The owned launcher builds/copies and proves strict artifact/process identity and exit/listener closure, using OS-assigned ports. Normal cleanup is not fault-injected recovery.

No previous evidence or approval is rewritten. Raw credentials/identities/messages are never public. Projected comparisons remain recorder testimony, not independent token-signature evidence. Other weak values, Unicode, null/empty, full policy boundaries, SDK/Rules, MFA and actual expiry remain separate future verification, not exclusions from the compatibility goal.
