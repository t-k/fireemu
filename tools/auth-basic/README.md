# Bounded Auth basic observations

This independent recorder exercises email/password signup, signin, account lookup, wrong-password refusal, selected stable state after refusal, SecureToken refresh, lookup using the refreshed token, client deletion and exact Admin absence readback. It does not test SDKs, MFA, tenants, OOB messages, Rules or the public npm package. Results are unapproved candidate observations, not a general Auth compatibility claim.

## Safety and evidence boundaries

Production is fixed to `fireemu-35fe6` / `592603257417`. Read-only preflight checks project identity, password provider settings, improved email privacy, absence of blocking triggers and an empty Cloud Functions list. Requests use project-bound API keys and a request-local quota project header. No IAM, ADC configuration or Firebase settings are modified. See the [quota-project REST documentation](https://docs.cloud.google.com/docs/authentication/rest#set_the_quota_project_with_a_rest_request).

Each run uses a random reserved-domain email and an independent random display-name ownership marker. The [signup contract](https://docs.cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signUp) permits the marker at account creation. Exact Admin absence is required before creation. A private, exclusive, fsynced journal is written before the request. Cleanup requires matching email, marker and UID, followed by exact UID and email absence checks; it never enumerates or batch-deletes accounts. Empty reads after an indeterminate signup do not prove cleanup: retain the journal and reconcile it later. Configuration and trigger checks are point-in-time checks, not protection against concurrent administrator changes.

Passwords, API keys, raw responses, ID tokens and refresh tokens remain in memory. Receipts contain allowlisted semantic booleans; these projections cannot independently reproduce raw-response validation or prove JWT signatures. Successful authenticated lookup demonstrates the measured service accepted the token. Keep recovery journals private. Never publish an entire output directory.

The local launcher builds and copies the exact artifact, uses a strict configuration and OS-assigned ports, verifies control-token challenges and parent PID, and checks process exit and listener closure. Its build receipt is separate from the recorder input hashes. Existing aggregation-bound tools are imported read-only and included in the new recorder input map; no prior approvals transfer to Auth.

## Commands

Run from the repository root. Output directories must be new and private.

```sh
uv run --project tools/compat-inventory --locked -m pytest tools/auth-basic -q
AUTH_BASIC_LIVE_LOCAL=1 uv run --project tools/compat-inventory --locked -m pytest tools/auth-basic -q
uv run --project tools/compat-inventory --locked tools/auth-basic/owned.py --output /private/new-local-output
uv run --project tools/compat-inventory --locked tools/auth-basic/recorder.py --production --output /private/new-production-output
uv run --project tools/compat-inventory --locked tools/auth-basic/recorder.py --production --recover /private/prior-output/recovery.json
```

Recovery reports unresolved if no owned UID can be established. Do not delete an unrelated account or close an unresolved journal based on repeated empty reads. A failed semantic expectation and incomplete execution are distinct; the process exit indicates completion, so inspect every case result as well.
