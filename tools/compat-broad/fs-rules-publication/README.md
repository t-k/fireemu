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

Re-run the local shadow, which builds `fireemu` and starts one owned instance:

```text
uv run --python 3.12 python \
  tools/compat-broad/fs-rules-publication/o5_user_token_local_run.py \
  --run /absolute/private/o5-user-token-shadow
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
| `o5_user_token_case.py` | Compiles the 26-row matrix, both Ruleset sources, the owned documents and accounts, every frozen payload and the expected result of every row |
| `o5_user_token_collector.py` | Runs the matrix through an injected transport under an enforced request ceiling, separate observation and recovery deadlines, an fsynced journal and version-bound cleanup of documents and accounts |
| `o5_user_token_campaign.py` | Freezes the inputs, the budget estimate, the permission envelope and the owner preconditions; admission always raises |
| `o5_user_token_comparator.py` | Names why a pair of bundles is not an acquisition; it has no positive classification |
| `o5_user_token_shadow.py` | Fixes the owned local `fireemu` launch specification and turns local deviations into repair tickets |
| `o5_user_token_local_run.py` | Executes the shadow: builds `fireemu` from this worktree, creates the accounts and fixtures, publishes each Ruleset, drives the matrix with real ID tokens and recovers everything |

The frozen template of the matrix is
[`spec/compatibility/fs-rules-user-token-matrix.json`](../../../spec/compatibility/fs-rules-user-token-matrix.json),
the executed local shadow record is
[`spec/compatibility/fs-rules-user-token-local-shadow.json`](../../../spec/compatibility/fs-rules-user-token-local-shadow.json),
and the preparation is described in
[`docs/compatibility/fs-rules-user-token-campaign-preparation.md`](../../../docs/compatibility/fs-rules-user-token-campaign-preparation.md).

### Redaction is structural

A compiled operation carries a credential *reference* label, never a token, so
the collector never holds an ID token, a refresh token, an API key or a
password. The transport resolves the label. Every receipt is scanned
recursively: a credential-shaped key or a token-shaped value at any depth
aborts the run, and observation and recovery receipts share one allowlist. A
row is bound to its principal by a per-nonce fingerprint derived from the
label, not from any secret. Nothing is passed on a command line.

### What this package does not do

It acquires no production credential, publishes no production Ruleset, creates
no production account and sends no production request. It is not an execution
permission: `admission` raises `PermissionError` and lists the blockers.

The comparator has no positive classification: every call returns
`INDETERMINATE` and names the acquisition bindings a bundle is missing. A
locally collected bundle labelled with the production role therefore cannot
reach agreement. Re-opening positive classification is a separate review.

The local shadow does start a process, create local accounts and publish local
Rulesets, all against one owned `fireemu` instance on loopback ports. That is
local evidence about `fireemu` and says nothing about production.

Publishing Rules changes the whole database's Rules state, so the campaign
manifest states the preexisting release capture and the recovery owner as owner
preconditions rather than implementing them here.
