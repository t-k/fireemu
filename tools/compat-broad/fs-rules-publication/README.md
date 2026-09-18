# O5 Firestore Rules publication and user-token preparation

This directory holds two offline preparation packages for `FS-RULES`. Neither
executes anything. The only status either one reaches is `PREPARATION_ONLY`,
`productionExecuted` and `productionReady` are false everywhere, and no
production comparison result exists.

Run the offline checks with:

```text
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/fs-rules-publication
uvx ruff check tools/compat-broad/fs-rules-publication
uvx ruff format --check tools/compat-broad/fs-rules-publication
```

## Ruleset publication case (`o5_rules_*`)

An offline, non-executable observation case for
`FS-RULES-PUBLICATION-USER-TOKEN-01`. Its comparator always returns
`INDETERMINATE`, because no typed collector or provenance validator was
reviewed for it. The template digest checks the consistency of that design
artifact, not the authenticity of any evidence.

The logical A→B sequence keeps six intended user SDK observations: three
owned-document successes under A, then an owned-document denial, a
public-document success and a second-user owned-document denial under B. Rules
source and resource paths illustrate the case; they are not a publication plan.
The project, database, nonce, user identities, source bytes, SDK build and
execution window have not been verified or reserved. A syntactically valid
nonce does not prove freshness. No wire request, cost, retention or time bound
is enforced.

## User-token observation matrix (`o5_user_token_*`)

A larger, bounded preparation for `FS-RULES-USER-TOKEN-MATRIX-01`. It prepares
the campaign that `FS-RULES` is actually blocked on: Rules evaluated with
end-user identity tokens, which administrator REST evidence cannot substitute
for, because an administrator bypasses Rules evaluation.

| Module | Responsibility |
| --- | --- |
| `o5_user_token_case.py` | Compiles the 25-row matrix, both Ruleset sources, the owned scope and the expected status of every row |
| `o5_user_token_collector.py` | Runs the matrix through an injected transport under an enforced request ceiling, monotonic deadline and version-bound cleanup |
| `o5_user_token_campaign.py` | Freezes the inputs, the budget estimate, the permission envelope and the owner preconditions; admission always raises |
| `o5_user_token_comparator.py` | Joins one production bundle with one local shadow bundle and classifies each row |
| `o5_user_token_shadow.py` | Fixes the owned local `fireemu` launch specification and turns local deviations into repair tickets |

The frozen template of the matrix is
[`spec/compatibility/fs-rules-user-token-matrix.json`](../../../spec/compatibility/fs-rules-user-token-matrix.json),
and the preparation is described in
[`docs/compatibility/fs-rules-user-token-campaign-preparation.md`](../../../docs/compatibility/fs-rules-user-token-campaign-preparation.md).

### Redaction is structural

A compiled operation carries a credential *reference* label, never a token, so
the collector never holds an ID token, a refresh token, an API key or a
password. The transport resolves the label. A receipt containing any
credential-shaped key is rejected as a leak, the run aborts, and no later row
is attempted. A row is bound to its principal by a per-nonce fingerprint
derived from the label, not from any secret. Nothing is passed on a command
line.

### What this package does not do

It acquires no credential, publishes no Ruleset, creates no account, starts no
process and sends no request. It is not an execution permission: `admission`
raises `PermissionError` and lists the blockers. A `MATCH` from the comparator
is agreement between two collected bundles, not a compatibility verdict;
`promotionReady` is always false and promoting this lane is a separate review.
Publishing Rules changes the whole database's Rules state, so the campaign
manifest states the preexisting release capture and the recovery owner as owner
preconditions rather than implementing them here.
