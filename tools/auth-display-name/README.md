# Bounded Auth displayName observations

This slice covers end-user REST displayName setting, replacement, malformed-token refusal, selected-state preservation and clearing with `deleteAttribute: ["DISPLAY_NAME"]`, with update responses and subsequent lookups checked separately. It records twelve cases including dedicated-account signup and cleanup. The original signup ID token is reused. `returnSecureToken` is omitted on profile updates; new token issuance is not checked.

## Ownership transition

The initial random displayName marker establishes ownership only during bootstrap. Exact email and independent UID lookups must agree with that marker. The recorder exclusively saves `verified-account.json` alongside `recovery.json`, then reads it back before any displayName mutation. From that point, exact saved UID and email identify the account, irrespective of changed or absent displayName. Reusing the same email with a different UID does not pass ownership checks.

Recovery with no saved UID requires the original marker on an extant account, cross-checks UID and saves it before deletion. An absent account with unknown UID remains unresolved. Recovery with verified identity uses both UID and email to identify the extant account or confirm absence after deletion. Private files must agree, be regular files, reject symlinks and forbid group/other permissions. These operator-controlled files are not cryptographic attestations. Keep both private files; never publish them.

Automatic cleanup after an interrupted signup follows the same persistence-before-delete rule as explicit recovery. If identity persistence or readback fails, cleanup refuses to delete the extant account and reports unresolved cleanup for a later retry. No production interruption is deliberately injected by this bounded observation.

## Projection and limits

Fixed names are `Fireemu display first`, `Fireemu display second` and the refused request's `Fireemu display refused`. The public enum distinguishes `initial`, `first`, `second`, `absent`, `null`, `empty`, `other` and `invalid-type`. Arbitrary returned names, account identities and credentials are not copied. The publisher rechecks enum/check/status consistency and bound source/corpus/artifact/configuration; it cannot independently reconstruct the redacted raw account comparisons.

The initial marker is a populated name, so setting tests replace that bootstrap value; an initially absent displayName is not the starting condition. Null and empty are distinct output classifications, not tested input writes. Exact JSON omission after clearing is a corpus hypothesis to compare with production, not inferred from the documented clearing alone. Unicode/length boundaries, provider synchronization, profile-update token issuance, expired-token refusal, independent signatures, SDK, MFA, Rules, tenants, credentials and full profile/Auth compatibility are excluded.

The versioned lifecycle and publisher intentionally preserve previously bound source files. Old Auth and aggregation approvals do not apply to this new candidate. No new generic evidence framework is introduced.

## Commands

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-display-name -q
AUTH_DISPLAY_NAME_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-display-name -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-display-name/display_name_owned.py --output /private/new-display-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-display-name/display_name_recorder.py --production --output /private/new-display-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-display-name.py --local /private/new-display-local/local.json --production /private/new-display-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-display-name.py --check
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-display-name/display_name_recorder.py --production --recover /private/run/recovery.json
```

Outputs are new private directories; local execution owns a copied strict artifact and OS-assigned port0 listeners. Production remains restricted to `fireemu-35fe6` / `592603257417`, one random account, read-only settings preflight, no blocking triggers or deployed functions, and journal-before-signup. No settings/IAM change, mail or pre-existing account edits. Semantic mismatches remain visible candidates, while incomplete observation, failed cleanup or process shutdown prevents publication. No automatic human approval.
