# Unicode password upper-bound diagnostic

Eight generated inputs distinguish scalar, UTF-8-byte and UTF-16-unit upper-bound hypotheses at4096. Each uses a private random32-character ASCII prefix, with repeated ASCII a, U+00E9 or U+10400 suffix. Each input has its own dedicated random account. Outcomes are observed rather than assumed; valid acceptance requires new-password signin and update-issued ID/refresh use, while valid refusal requires continued use of fixed baseline ID/refresh/password. Both paths check selected account fields, token expiry fields and confirmed cleanup.

The recorder imports frozen maximum HTTP/ownership helpers without modifying them, and binds their hashes together with its own sources. Eight isolated private journals are retained. Configuration is read before/after without writes. An inconclusive request or unresolved cleanup stops further accounts. Raw passwords, tokens and account identifiers are never published.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-unicode/unicode_owned.py --output /absolute/private/new-local
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-unicode/unicode_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-password-unicode/unicode_recorder.py --production --recover /absolute/private/new-production/SAMPLE-ID/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-unicode.py --local /absolute/private/new-local/local.json --production /absolute/private/new-production/observation.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/publish-auth-password-unicode.py --check
AUTH_PASSWORD_UNICODE_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-password-unicode/test_unicode_owned.py -q
```

Only one sample journal may be recovered at a time; sample IDs are the fixed corpus labels. This diagnostic does not cover normalization, grapheme clusters, isolated surrogates, all Unicode strings, the minimum boundary, SDK/Rules or elapsed expiry. Existing observations and approvals remain unchanged. Candidate counting hypotheses fit only the observed finite pattern; none is a universal proof or a human approval.
