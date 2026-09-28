# Bounded Auth photo URL observations

This recorder tests only `photoUrl` through end-user REST APIs: signup, initial lookup, set, lookup, replacement, lookup, malformed-token refusal, unchanged-state lookup, `deleteAttribute: ["PHOTO_URL"]`, lookup, account deletion and exact UID/email absence. It does not edit `displayName`, which remains the dedicated account's ownership marker. `returnSecureToken` is omitted on profile updates; the original signup token is reused. Token issuance on profile updates is not tested.

The fixed URLs are `https://example.invalid/fireemu-profile-first.png`, `https://example.invalid/fireemu-profile-second.png` and the refused update's `https://example.invalid/fireemu-profile-refused.png`. The recorder does not retrieve images. The public projection retains only a closed photo-state enum: `first`, `second`, `absent`, `null`, `empty`, `other` or `invalid-type`. Empty and null are not silently treated as omission. HTTP/check consistency is recomputed offline, while source-response classification and identity comparisons remain redacted recorder observations, not independently replayable raw evidence.

The reviewed lifecycle/provenance code is versioned separately because old approved subjects bind their recorder and publication source. Changes here do not rewrite the Auth basic or aggregation receipts. This duplication is intentional evidence preservation, not a new generic evidence framework. Source mapping uses slice-local obligations and distinguishes documented clearing from the exact omission hypothesis.

## Execution and safety

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-profile -q
AUTH_PROFILE_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-profile -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-profile/profile_owned.py --output /private/new-profile-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-profile/profile_recorder.py --production --output /private/new-profile-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-profile.py --local /private/new-profile-local/local.json --production /private/new-profile-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-profile.py --check
```

Use new private output directories. The strict runner owns a freshly built copied artifact and uses OS-assigned port0 listeners. Production is restricted to `fireemu-35fe6` / `592603257417`, read-only preflight of email/password and privacy settings, no blocking triggers or deployed functions, one random account and journal-before-signup. No settings or IAM changes, no mail or existing-account edits. Failure and cleanup exceptions retain only exception classes. An unknown signup result cannot become cleanup success merely because an email lookup is empty.

Retain private recovery journals; never publish the output directory or raw Auth responses. Recovery is `profile_recorder.py --production --recover /private/run/recovery.json`, with exact ownership checks. See the [original safety contract](../auth-basic/README.md). Complete semantic mismatches remain visible candidates; incomplete execution and cleanup failure are ineligible. There is no automatic approval and no claim about credentials, URL validation, provider synchronization, elapsed token expiry, SDK, Rules, MFA, tenants, public npm or complete Auth compatibility.

Once ownership is verified, `verified-account.json` privately preserves the UID alongside the original journal identity. Keep both files together. Recovery requires exact agreement and private regular-file permissions; a saved UID permits both-selector absence checks after a successful deletion whose final readback was interrupted. Without verified UID or an extant owned account, recovery remains unresolved.
