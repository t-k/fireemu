# Supplementary-character password boundary

This separate corpus observes three generated patterns at 4095, 4096 and 4097 UTF-16 units. Each starts with a private random 32-character URL-safe ASCII prefix, followed by U+10400 repeated 2031 or 2032 times and zero or one ASCII a. Actual scalar, UTF-8 byte and UTF-16 unit lengths are checked before requests and in publication. Different accounts and prefixes are used across inputs and runs; this is not a comparison of identical secret strings.

Each dedicated account first proves usable baseline credentials. Acceptance requires the generated password and update-issued ID/refresh credentials to work. Refusal requires the fixed baseline ID/refresh/password to remain usable. Selected account state is checked throughout. The two lower-boundary inputs supply positive controls on separate accounts, not a valid update following refusal on the same account. Unknown errors, incomplete controls and unresolved cleanup stop the suite and cannot be published. The private journal precedes account creation; saved UID and email bind cleanup, with both absence checks required.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-unicode-boundary/boundary_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-unicode-boundary/boundary_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-unicode-boundary/boundary_recorder.py --production --recover /absolute/private/new-production/CASE/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-unicode-boundary.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-unicode-boundary.py --check
AUTH_PASSWORD_UNICODE_BOUNDARY_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password-unicode-boundary -q
```

Only the configured oracle project is used; settings are read before/after without writes. Raw tokens/passwords are never published. The owned launcher builds, copies and identifies its artifact, then confirms exit and listener closure. Existing Unicode observations and approvals remain unchanged. This corpus is a candidate, not human-approved coverage of all Unicode, normalization, alternative-password truncation, signup/Admin/reset/minimum rules, expiry, SDK/Rules or injected-failure recovery.
