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
| `o5_user_token_collector.py` | Runs the matrix through an injected transport under an enforced request ceiling, separate observation and recovery deadlines, an fsynced journal and version-bound cleanup of documents and accounts; in a bound run it also releases each Ruleset through a checked step and records the endpoint, wire sequence, clocks, observer digests and launcher bindings the acquisition comparator verifies |
| `o5_user_token_campaign.py` | Freezes the inputs, the budget estimate, the permission envelope and the owner preconditions; admission always raises |
| `o5_user_token_comparator.py` | Names why a pair of bundles is not an acquisition; it has no positive classification |
| `o5_user_token_comparator_v2.py` | The acquisition comparator: reaches `MATCH`, `SEMANTIC_MISMATCH`, `INDETERMINATE` or `REFUSED`, and reaches a positive classification only when every binding below is present on both sides and verified |
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

### Bound collection

`collect(..., acquisition=...)` runs the matrix as an acquisition attempt
rather than a recording. The launcher supplies the environment kind, the
campaign manifest digest, the nonce reservation or the artifact, the principal
fingerprints and the approval window; the collector validates their shape,
scans them for credential-shaped content, refuses an environment that
contradicts the role, and records a copy. During the run every receipt must
carry `endpoint` (the host and port the transport connected to) and
`wireSequence` (the transport's own request counter); a receipt without them,
an endpoint outside the declared environment's allowlist, or a sequence that
regresses aborts observation and is refused again during recovery, so no
deletion is authorized on the strength of a foreign endpoint. Before the first
row of each Ruleset the collector issues an explicit `ruleset-release` request
carrying the plan's source digest, and accepts the release only when the
transport's readback digest equals it. The bundle records `observer` (the lane
source digests, read from disk), `transport` (endpoints, receipt and sequence
counts, the releases, the monotonic and wall clocks) and `acquisition`, and
derives `productionExecuted` from the endpoints reached rather than from any
label. An unbound run behaves as before: no release step, no acquisition, and
the wire keys are optional. Structural redaction is unchanged in both modes.

The local runner is the lane's only bound transport. Its `_request` records
the loopback host and port and the process-wide request counter after its
loopback check, and every receipt it returns carries them. Its Ruleset
readback is a publish echo, labelled `publish-echo`, because the local runtime
has no route that reads the active release back; the acquisition comparator
accepts that on the local side only and requires a `release-get` on the
production side.

### What this package does not do

It acquires no production credential, publishes no production Ruleset, creates
no production account and sends no production request. It is not an execution
permission: `admission` raises `PermissionError` and lists the blockers.

The first comparator has no positive classification: every call returns
`INDETERMINATE` and names the acquisition bindings a bundle is missing. A
locally collected bundle labelled with the production role therefore cannot
reach agreement there. Positive classification lives in the separately
reviewed second module described below, and only behind the bindings it
verifies.

### Comparator v2 (acquisition comparator)

`o5_user_token_comparator_v2.py` is the second comparator module. The first
module is unchanged and its `test_no_success_vocabulary_exists_in_the_module`
still holds: the two modules record two different decisions. The first says a
recording is not an acquisition. The second says what an acquisition has to
bind, checks each binding against something the bundle cannot fabricate, and
compares rows only after both sides are admitted.

`compare(production, local, plan, *, manifest_digest=None)` returns
`classification` in `MATCH`, `SEMANTIC_MISMATCH`, `INDETERMINATE`, `REFUSED`,
the 26 per-row decisions, a per-condition summary, and `errors` naming every
binding that failed, prefixed with the side (`production:` or `local:`) or
unprefixed when it concerns the pair.

| Binding | Verified against | Named error |
| --- | --- | --- |
| Collector identity | SHA-256 of every lane module in `_SOURCE_FILES`, recomputed from disk now | `observer-digest-drift` (refused) |
| Endpoint reached | Per receipt, from the transport: production side only `firestore.googleapis.com`, `identitytoolkit.googleapis.com`, `firebaserules.googleapis.com`; local side only loopback | `local-mislabelled-as-production`, `endpoint-outside-allowlist`, `local-reached-nonloopback` (refused), `missing-binding:endpoint:...` |
| Ruleset releases | Source digest equals the plan's Ruleset source; readback digest equals it; production readback is a `release-get`, not a publish echo; every row runs under the release most recently active before it | `ruleset-mismatch:<label>:...`, `ruleset-generation-order:<caseId>` |
| Principal provenance | Row fingerprint recomputed from the nonce and reference; per account a uid fingerprint, provider, tenant and claims digest matching the plan; fingerprints differ between sides | `principal-drift`, `principal-fingerprint`, `principal-mismatch:<ref>:...`, `principal-shared-across-sides` (refused) |
| Manifest digest | Recomputed from `o5_user_token_campaign.manifest()` for the production identity; equal on both sides; equal to the admitted digest when one is passed | `manifest-mismatch` (refused) |
| Cleanup proof | Every owned document and account: readback, delete under the observed version or uid, typed absence; no step failure; nothing outstanding | `cleanup-unknown:...` |
| Time and counts | Rows strictly monotonic and inside the observation span and deadline; wire sequence strictly increasing across releases, rows and recovery steps; receipt count equals the steps; `observationSpent`, `rulesetSpent`, `recoverySpent` equal the recorded steps; wall clock agrees with the monotonic span and lies inside the approval window | `time-contradiction:...`, `count-contradiction:...` |
| Reservation and permission | Production side: reservation id, campaign id and nonce digest; owner permission digest; approval window. Local side: artifact digest and source commit, and no reservation | `missing-binding:...`, `nonce-reservation-mismatch:...`, `local-claims-reservation` (refused) |
| Environment label | `acquisition.environment.kind` must agree with the role, the endpoints and the artifact binding | `local-mislabelled-as-production`, `local-claims-production` (refused) |
| Identity | Same run on both sides, a bundle claiming `productionReady` or `acquisitionValidated`, a role that is not the side it was passed as, a plan or case digest that is not the campaign's | `self-comparison`, `bundle-claims-authority`, `role-mismatch`, `case-digest-drift`, `campaign-identity-drift` (refused) |

An error in the refusal set makes the result `REFUSED`; any other error makes
it `INDETERMINATE`; neither carries rows. Only two admitted bundles are
compared, row by row, on status, document presence and field values, with a
field that resolves to a principal compared by presence rather than by uid,
because the two runs mint different accounts by construction.

The local shadow is compiled with the tenant identifier the local Auth
emulator assigned, so the local plan is recompiled from the bundle's own case
identity and must share the campaign's project, database and nonce. A local
bundle for another nonce is refused.

The module is listed in `o5_user_token_campaign._SOURCE_FILES`, so the campaign
manifest digest binds it and a change to it changes what a run is admitted
under. The frozen matrix template in `spec/compatibility` carries no source
digests, so it does not change with the module list.

The local shadow does start a process, create local accounts and publish local
Rulesets, all against one owned `fireemu` instance on loopback ports. That is
local evidence about `fireemu` and says nothing about production.

Publishing Rules changes the whole database's Rules state, so the campaign
manifest states the preexisting release capture and the recovery owner as owner
preconditions rather than implementing them here.
