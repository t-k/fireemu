# Auth basic revision 2

This versioned recorder preserves revision1's evidence-bound source files. Its lifecycle code is intentionally retained separately so the historical nine-case bundle remains checkable without rewriting its provenance. Transport, account ownership and process cleanup retain the prior safety constraints; there is no new generic evidence management framework.

Revision2 adds `signup-token-lookup`, `signup-token-refresh` and `signup-refreshed-lookup` to the original nine cases. Token values are only used in memory. `expiryIsPositiveInteger` means a positive integer string of one to six digits; `expiryMatchesOneHour` means the returned field is exactly `3600`. Numeric expiry is safely retained so publication can recompute these predicates. A different positive lifetime remains a visible mismatch rather than stopping cleanup or hiding the observation. Actual token expiration and independent signature verification are not tested.

The [reviewed source mapping](../../spec/compatibility/evidence/auth-basic-v2/source-review.json) distinguishes source requirements from derived controls. The public receipt contains allowlisted process identity, exit, immutable configuration and build-input evidence; it is not a signature or proof against a malicious recorder. It preserves the limits of redacted response predicates. There is no automatic human approval.

```sh
uv run --project tools/compat-inventory --locked -m pytest tools/auth-basic-v2 -q
AUTH_BASIC_V2_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked -m pytest tools/auth-basic-v2 -q
uv run --project tools/compat-inventory --locked tools/auth-basic-v2/auth_v2_owned.py --output /private/new-local-output
uv run --project tools/compat-inventory --locked tools/auth-basic-v2/auth_v2_recorder.py --production --output /private/new-production-output
uv run --project tools/compat-inventory --locked tools/publish-auth-v2.py --local /private/new-local-output/local.json --production /private/new-production-output/observation.json
uv run --project tools/compat-inventory --locked tools/publish-auth-v2.py --check
```

Production project, read-only preflight, random ownership marker, journal-before-signup, exact lookup cleanup and indeterminate-creation recovery follow the [revision1 safety contract](../auth-basic/README.md). Recovery uses this version's recorder with `--production --recover /private/run/recovery.json`. Never publish recovery journals or a whole output directory. No IAM/Firebase settings changes, OOB messages, SDK, Rules, tenant, MFA or public npm coverage are implied.
