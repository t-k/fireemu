# Shared local execution gate and combined observation proposal

The fixed implementation/execution is `e50a1aaf`. The existing `batch_local.py --shared` entry runs two closed scenarios through `batch_adapter.Adapter.request`, with one coordinator, two worker processes and two disjoint owned namespaces. HTTP callbacks are conservatively serialized under a stable file lock; this is two scenario slots, not two simultaneous HTTP requests. No daemon, database, DSL or production operation was introduced.

## Executed scenarios

| Scenario | Diagnostic and state observation | Observation / recovery HTTP requests | Result |
| --- | --- | --- | --- |
| `partial` | BatchWrite with three distinct targets: the middle exists=false precondition is refused; prefix/suffix persist and the existing document remains7 | 8 / 9 | Recording, local state invariant and cleanup complete |
| `transaction-field` | BatchWrite carrying a transaction field; the seeded guard remains3 after the refusal | 4 / 3 | Recording, local state invariant and cleanup complete |

Both ran against the same owned artifact. Two local ownership-control requests are prepaid and gated before either worker claims its scenario. The total is26 operations:12 observation data requests,12 recovery requests and2 ownership-control requests. Recovery is a subset of total, not added a second time. Four documents were journaled and confirmed absent after cleanup; no Auth account was created. The adapter response receipts match the gate request digests, status and response digests. Local response values are retained as observations, not substituted for missing production expectations.

See the [execution record](../../spec/compatibility/broad-runs/e50a1aaf-shared-local.json) for exact manifests, hashes, diagnostic responses, counters, test results and process cleanup. The artifact is `4b231b7931a05dd763662b93c6508152f7eaa66db4bf090aaab97e51fd870996`; use the JSON's `artifactSha256` as the authoritative identity. The first46 regression uses its separately recorded artifact from the same fixed source; the two binary hashes are not conflated.

## Admission and failure behavior

The gate binds the exact operation, method, body, principal, local origins, manifest nonce and observer digest before the existing adapter's authentication/reservation/transport path. A missing gate, changed binding, unknown operation or unavailable lock never falls back to unmanaged traffic. Every admitted operation still passes the adapter's individual budget. This first closed frame admits no Auth or remote metadata operations, so their actual counts are zero; arbitrary additional operations cannot use a generic bypass flag.

The initial allocation reserves all12 recovery requests and a159-second serialized recovery allowance before claims. The local frame is300 seconds including180 seconds reserved for recovery. Observation may stop when its120-second window is exhausted; slow observations cannot consume the recovery window. Global spacing is at least250ms after the preceding callback finishes, which is stricter than four request starts per second. One13-second operation allowance includes the existing12-second wire deadline and local adapter spacing. File-lock waiting is bounded and deadlines are rechecked after rate waits.

A durable debit and in-flight marker precede transport. Worker death retains ownership and uncertainty; lock release is not treated as transport completion. Uncertain in-flight work blocks all further dispatch, including recovery, until separately quiesced. A completed ordinary failure stops that scenario's observation but preserves independent work and reserved recovery. Recovery is one-way: later observation cannot recreate cleaned resources. No worker exit or TTL releases ownership.

Cleanup DELETE requires a valid readback updateTime. A404, unavailable read or missing/invalid version skips DELETE and still permits the final absence read and independent target cleanup. No synthetic HTTP success is recorded for a skipped operation. Failure to prove final absence retains the resource and marks cleanup incomplete. Private journals and partial response files survive errors; the wrapper preserves initial artifact/configuration identity and records process/listener shutdown separately.

## Verification and review

- The existing compatibility CI already runs all `tools/compat-broad` tests; the added tests therefore execute without a new CI framework. Final suite:231 passed, zero failed/skipped,75.76 seconds. Ruff and ty passed for the changed modules.
- Real spawned processes exercise last-capacity contention, crash-retained ownership, and both scenarios recovering after observation exhaustion. Additional controls cover duplicate ownership, local/global stops, wrong operation, remote-origin rejection, deadlines, cost reservation, non-JSON/partial-body/credential refusal through the existing wire, absent/missing-version cleanup and undersized recovery-time allocation.
- Four isolated Python mutations were killed: recovery cost reservation, absent-target DELETE suppression, uncertain-marker retention and recovery-time admission. A separate worktree and guarded target/build directories were used; no Cargo mutation build ran and no mutation output became a normal artifact.
- Independent security review approved the final local-only delta. Earlier findings—unconditional DELETE after404, recovery cursor blockage and nonce mismatch—were corrected and rechecked. A later arithmetic check enlarged the recovery reservation and added a failing-before-fix test.
- First46 executed successfully with all46 rows and owned-process cleanup. This is a local regression run, not a new production comparison. No runtime source or comparator semantics changed; second45 and other historical receipts were not rerun or overwritten.

The unsuccessful wrapper result at54fb44fc, nonce-rejected run at eba5d8ed, and earlier cc7000ad run remain private historical results with their original limitations. Their completion status and hashes were not rewritten.

## One combined production proposal

The [combined input proposal](../../spec/compatibility/broad-runs/e50a1aaf-shared-execution-proposal.json) contains both recipes, target environment, collector identity, configuration contract, budgets, cost calculation and outstanding decisions. It proposes one execution of each scenario, two scenario slots, one in-flight HTTP request, four requests/second globally, four owned documents and zero accounts/configuration changes. There is no automatic retry or reobservation.

Proposed total capacity is34 operations:24 data requests plus10 bounded credential/metadata operations, including command invocations.18 are observation and16 recovery. Production recovery reserves300 seconds:15 HTTP operations at13.25 seconds plus one globally coordinated60-second credential command total258.75 seconds. Independent per-worker refresh is excluded; allowing two refreshes would require a different allocation. This arithmetic is a proposal, not a claim that Cloud credentials or settings were checked.

The planning calculation includes16 reads,6 writes,4 deletes, no scans/index reads, four documents with worst-case index storage, and34 bounded responses. Firestore bills document operations, storage/index overhead and bandwidth, so HTTP count alone is not the cost model. The conservative ceiling-rate calculation is approximatelyUSD0.03371; USD0.04 fixed plusUSD0.0001 per operation reservesUSD0.0434. A proposedUSD1 owner budget is unset for acceptance and is not an invoice hard cap. No free quota is deducted. Storage is conservatively calculated for one month despite the proposed24-hour manual recovery obligation. See the official [pricing description](https://firebase.google.com/docs/firestore/pricing) and [8MiB per-document index-size limit](https://firebase.google.com/docs/firestore/quotas).

Owner identity, permission reference, period, new production nonce, recovery owner, accepted Database projection/Auth digest, current location and tariff acceptance are all unset. The adapter must not turn preflight output into an approved baseline. Public pricing was read; no Cloud configuration or authentication read occurred.

The current executable entry remains deliberately local-only. Before any production execution, a distinct production admission must bind this combined proposal and its metadata operations to the existing credential/preflight path and receive review of that activation delta. Removing the local guard alone is not an activation mechanism. This technical activation condition is explicit in the proposal; approval is not being requested for arbitrary code or inherited first46/second45 permissions.

## Timing and resumption

Work began at2026-09-13T13:44:28+09:00. The final validation/process check was at2026-09-13T14:13:11+09:00. Command-reported compile times were5.45 seconds for shared execution and2.15 seconds for the final first46 build; actual scenario elapsed time and mutation timestamps are in the record. Preparation, analysis and review durations were not separately instrumented and remain unknown. No estimated durations are substituted.

Resume with the narrowly scoped production activation/binding review and owner decision package, retaining the local-only default. The gate and both actual local scenarios are implemented and verified; no additional case exploration is needed to establish that local milestone. Unknown production BatchWrite responses remain candidate questions, not runtime gaps. Existing45/46 evidence, revision3 and independent MFA/TTL work retain their prior classifications.
