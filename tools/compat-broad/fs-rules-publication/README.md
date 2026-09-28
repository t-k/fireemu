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

Re-run the local shadow, which builds `fireemu` and starts one owned instance.
Run it on a committed tree, because the record binds the source commit and the
digests of the manifest-bound lane modules; wrapping it in
`scripts/cargo-session` routes the build to a session target directory:

```text
scripts/cargo-session --session <name> -- uv run --python 3.12 python \
  tools/compat-broad/fs-rules-publication/o5_user_token_local_run.py \
  --run /absolute/private/o5-user-token-shadow
```

The checked-in record is the child's `local-shadow.json` with the parent's
`artifact`, `exitCode` and `originsClosed` from `parent-result.json` added.

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
| `o5_user_token_case.py` | Compiles the 33-row matrix, both Ruleset sources, the owned documents and accounts, every frozen payload and the expected result of every row; the seven `credential-revocation` rows also carry a stated production hypothesis, and three of them name the administrator step the collector performs before them |
| `o5_user_token_collector.py` | Runs the matrix through an injected transport under an enforced request ceiling, separate observation and recovery deadlines, an fsynced journal and version-bound cleanup of documents and accounts; in a bound run it also releases each Ruleset through a checked step and records the endpoint, wire sequence, clocks, observer digests and launcher bindings the acquisition comparator verifies |
| `o5_user_token_campaign.py` | Freezes the inputs, the budget estimate, the permission envelope and the owner preconditions; admission always raises |
| `o5_user_token_comparator.py` | Names why a pair of bundles is not an acquisition; it has no positive classification |
| `o5_user_token_comparator_v2.py` | The acquisition comparator: reaches `MATCH`, `SEMANTIC_MISMATCH`, `INDETERMINATE` or `REFUSED`, and reaches a positive classification only when every binding below is present on both sides and verified |
| `o5_user_token_shadow.py` | Fixes the owned local `fireemu` launch specification and turns local deviations into repair tickets |
| `o5_user_token_local_run.py` | Executes the shadow: builds `fireemu` from this worktree, creates the accounts and fixtures, publishes each Ruleset, drives the matrix with real ID tokens and recovers everything |
| `o5_user_token_descriptor.py` | The O8 `CampaignDescriptor` for `FS-RULES-USER-TOKEN-MATRIX-01`: schema kinds, window, source map, plan compiler, budget, Ledger lock scopes, the bound collector and the acquisition comparator; the wire members refuse |

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
`wireSequence` (the transport's own request counter); before a row that
names a `principalAction` the collector issues an explicit administrator step
(`phase: principal`) and accepts it only when the transport's readback proves
the action (`present`, `disabled`, `uidFingerprint` equal to the launcher's
binding, `authTime`, and `validSince` after `authTime` for a revoke); a
receipt without the wire facts,
an endpoint outside the declared environment's allowlist, or a sequence that
regresses aborts observation and is refused again during recovery, so no
deletion is authorized on the strength of a foreign endpoint. Before the first
row of each Ruleset the collector issues an explicit `ruleset-release` request
carrying the plan's source digest, and accepts the release only when the
transport's readback digest equals it. The bundle records `observer` (the lane
source digests, read from disk), `transport` (endpoints, receipt and sequence
counts, the releases, the monotonic and wall clocks) and `acquisition`, and
derives `productionExecuted` from the endpoints reached rather than from any
label. An unbound run behaves as before: no release step, no principal
action, no acquisition, and the wire keys are optional. Structural redaction is unchanged in both modes,
and `_scan` also refuses the non-JWT Google credential prefixes `ya29.`,
`AIza` and `1//`.

In both modes the collector replaces every account identifier its recovery
readbacks returned with the principal label `principal:<ref>`, in rows and in
recovery steps, and lists the labels under `redactedPrincipals`; the raw uid
is used only for the delete precondition and never reaches the bundle. The
local runner's own redaction after collection remains as a second pass, and
its frozen-field check resolves `$principal` to the label.

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
the 33 per-row decisions, a per-condition summary, a per-condition hypothesis
tally, and `errors` naming every
binding that failed, prefixed with the side (`production:` or `local:`) or
unprefixed when it concerns the pair.

| Binding | Verified against | Named error |
| --- | --- | --- |
| Collector identity | SHA-256 of every lane module in `_SOURCE_FILES`, recomputed from disk now | `observer-digest-drift` (refused) |
| Endpoint reached | Per receipt, from the transport: production side only `firestore.googleapis.com`, `identitytoolkit.googleapis.com`, `firebaserules.googleapis.com`; local side only loopback | `local-mislabelled-as-production`, `endpoint-outside-allowlist`, `local-reached-nonloopback` (refused), `missing-binding:endpoint:...` |
| Ruleset releases | Source digest equals the plan's Ruleset source; readback digest equals it; production readback is a `release-get`, not a publish echo; every row runs under the release most recently active before it | `ruleset-mismatch:<label>:...`, `ruleset-generation-order:<caseId>` |
| Principal actions | Exactly the plan's administrator steps, each with the action, `auth_time`, a `validSince` after `auth_time` for a revoke and none otherwise, a lookup readback showing what the action did (absent for a delete, present and disabled or not otherwise) whose uid fingerprint equals the launcher's principal binding, an allowlisted endpoint, and a timestamp between the positive-control row and the row that presents the token again | `principal-action:<ref>:...` |
| Principal provenance | Row fingerprint recomputed from the nonce and reference; per account a uid fingerprint (shape-checked: the comparator holds no uid), provider, tenant and claims digest matching the plan; uid fingerprints differ between sides; no uid-shaped string anywhere in the bundle | `principal-drift`, `principal-fingerprint`, `principal-mismatch:<ref>:...`, `principal-shared-across-sides` (refused), `unredacted-identifier` |
| Manifest digest | Recomputed from `o5_user_token_campaign.manifest()` for the production identity; equal on both sides; equal to the admitted digest when one is passed | `manifest-mismatch` (refused) |
| Cleanup proof | Every owned document and account: readback, delete under the observed version or uid, typed absence; no step failure; nothing outstanding | `cleanup-unknown:...` |
| Time and counts | Rows strictly monotonic and inside the observation span and deadline; recovery steps monotonic; wire sequence strictly increasing across releases, rows and recovery steps; receipt count and sequence summary equal the steps; `observationSpent`, `rulesetSpent`, `recoverySpent` equal the recorded steps and every ceiling and deadline is the collector's for this plan; wall clock agrees with the monotonic span and lies inside the approval window. No cost is checked | `time-contradiction:...`, `count-contradiction:...` |
| Reservation and permission | Production side: reservation id, campaign id and nonce digest; owner permission digest; approval window. Local side: artifact digest and source commit, and no reservation | `missing-binding:...`, `nonce-reservation-mismatch:...`, `local-claims-reservation` (refused) |
| Environment label | `acquisition.environment.kind` must agree with the role, the endpoints and the artifact binding | `local-mislabelled-as-production`, `local-claims-production` (refused) |
| Identity | Same run on both sides, a bundle claiming `productionReady` or `acquisitionValidated`, a role that is not the side it was passed as, a plan or case digest that is not the campaign's | `self-comparison`, `bundle-claims-authority`, `role-mismatch`, `case-digest-drift`, `campaign-identity-drift` (refused) |
| Observed record schema | Per row, `observed.status` is a non-empty string, `observed.documentPresent` is a JSON boolean, `observed.fields` is a mapping or absent, and the record is finite JSON with string keys; a number in a boolean slot is a malformed record, not a value | `row-unobserved:<caseId>`, `row-schema:<caseId>:status`, `row-schema:<caseId>:documentPresent`, `row-schema:<caseId>:fields`, `row-schema:<caseId>:not-json` |
| Principal identity in fields | A field the plan resolves to `{"$principal": "<ref>"}` is mapped to that logical reference through the side's own binding: the `principal:<ref>` label must be declared in the bundle's `redactedPrincipals`, name an account the plan owns, and be the identifier that account's recovery readback recorded; a string without that binding is unmapped and leaves the row indeterminate, never equal | `principal-unmapped:<caseId>:<field>` |

An error in the refusal set makes the result `REFUSED`; any other error makes
it `INDETERMINATE`; neither carries rows. Only two admitted bundles are
compared, row by row, on status, document presence and field values, by
type-preserving JSON equality (`1` and `true`, `1` and `1.0`, `0` and `false`
are different values at every depth). A field that resolves to a principal is
compared as the logical principal each side's binding maps it to
(`{"$principal": "owner-a"}` on both sides is a match, `owner-a` against
`other-b` is a `SEMANTIC_MISMATCH` on that row), because the two runs mint
different accounts by construction; a value neither binding maps is
`principal-unmapped` and the result is `INDETERMINATE` with the row marked
`INDETERMINATE`, `acquisitionValidated` false (the invariant is
`acquisitionValidated == (errors == [])`) and the condition summary following
the weakest row. `observed.code`
is recorded but not compared: the local transport never sets it and a
production transport's code vocabulary is unobserved. A production release
must be named by its Rules API resource (`projects/<p>/releases/<n>` or
`projects/<p>/rulesets/<id>`). `compare()` never raises on a malformed bundle:
a shape it did not anticipate is named `comparator-exception:<Type>` and left
`INDETERMINATE`.

Review record (2026-09-21, owner review d7f7ce184 findings 1 and 3): the
earlier projection replaced every non-empty string in a principal slot with a
placeholder, so a different owner, or an unrelated string, compared equal, and
rows were compared with Python equality, so `documentPresent: 1` matched
`true`. Both are closed by the two table rows above, with the tests in
`test_o5_user_token_comparator_v2.py` under "Principal identity in observed
fields" and "Typed JSON comparison of observed rows". The comparator contract
string moved to `fs-rules-user-token-comparator-v4` because the meaning of
`MATCH` changed.

Review record (2026-09-21, external RULES-SEMANTIC-REPAIR-006): the label-only
mapping accepted a field that carried the literal `principal:owner-a` before
redaction as the principal. The collector now records `principalFieldBindings`
per row before redaction, from the field value's equality with the uid a
successful account readback returned (`o5_user_token_semantics.py`,
`capture_principal_fields`); the comparator refuses a binding the readbacks do
not show (`principal-binding:<caseId>:<field>:...`) and maps a principal slot
only when the label and the binding agree. Typed JSON comparison lives in the
same module with bounded depth, node count, string length and integer size.
Collector contract `fs-rules-user-token-collector-v4`, comparator contract
`fs-rules-user-token-comparator-v5`; the local shadow was regenerated at
5f9b39710. Tests: `test_o5_user_token_semantics.py` (pure) and
`test_o5_user_token_semantic_admission.py` (collector to comparator).

Mutation record (2026-09-21): the three `local-mislabelled-as-production`
signals are each covered by one test that changes exactly one binding of the
real bound production bundle. Deleting the loopback refusal in
`_admit_endpoint` fails `test_signal_loopback_endpoints_alone_refuse_a_production_bundle`
(and the short-a-row test); deleting the environment-kind refusal in
`_admit_acquisition` fails `test_signal_local_environment_kind_alone_refuses_a_production_bundle`;
deleting the artifact refusal fails `test_signal_an_artifact_binding_alone_refuses_a_production_bundle`.
A 4000-mutation single- and multi-field fuzz of `compare()` over a bound pair
raised nothing and hit the exception backstop nothing.

The local shadow is compiled with the tenant identifier the local Auth
emulator assigned, so the local plan is recompiled from the bundle's own case
identity and must share the campaign's project, database and nonce. A local
bundle for another nonce is refused.

The module is listed in `o5_user_token_campaign._SOURCE_FILES`, so the campaign
manifest digest binds it and a change to it changes what a run is admitted
under. The frozen matrix template in `spec/compatibility` carries no source
digests, so it does not change with the module list.

### O8 descriptor

`o5_user_token_descriptor.py` declares the campaign to the shared O8 core in
`tools/compat-broad/o8-core`. It freezes the whole lane directory plus the
shared closure (`broad_contract.py`, `shared_gate.py`, the Ledger
`reservations.py`, `o8_admission.py`, `o8_campaign.py`), compiles the plan for
a nonce with the placeholder tenant, states the four Ledger budget dimensions
and the frozen bounds from the campaign manifest's own budget, holds the
database's ruleset key `EXCLUSIVE` in the Ledger because a Ruleset publication
changes the whole database, and wires the bound collector as the production
side and the acquisition comparator against the published local shadow. The
window is 600 seconds of observation plus 300 seconds of recovery, which is
the collector's 900 second recovery deadline.

`transport_bound` and `binding_verifier` refuse: the lane has no reviewed
production transport and no worker archive, so a descriptor built here can
freeze inputs and pass `validate_o7_admission` against a synthetic approval
and can do nothing else. `issue_production_capability` fails on the worker
binding. The lane's own `admission()` still raises. The artifact profile is
derived from the published shadow's source commit; it names which build the
comparison reference came from, not that the build was reviewed.

The local shadow does start a process, create local accounts and publish local
Rulesets, all against one owned `fireemu` instance on loopback ports. That is
local evidence about `fireemu` and says nothing about production.

Publishing Rules changes the whole database's Rules state, so the campaign
manifest states the preexisting release capture and the recovery owner as owner
preconditions rather than implementing them here.
