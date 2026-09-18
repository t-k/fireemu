# Firestore Write and transaction campaign preparation

## Current execution boundary

The Write/transaction campaign now has a bounded gRPC transport, shared Gate and Ledger admission, metadata coordinator, immutable acquisition receipt, and credential-free comparator. The reviewed execution source is `dee737c14e68eb4f546b7ca4c827871fc48a2503`. The owner-approved bounded campaign executed once on 2026-09-17 after fresh binding and O7 admission. The [immutable public result summary](../../spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json) records validated production acquisition and its original semantic mismatch. The single-iteration permission is consumed. `FS-DATA-WRITE` and `FS-TRANSACTION` remain below `COMPAT_VERIFIED`.

The earlier combined [`v9 package`](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9.json), [binding](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9-binding.json), and [local plan](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9-local-shadow.json) are historical preparation artifacts. Their bytes, earlier versions, source identities, and budgets remain unchanged. They are not the current executable stream envelope. In particular, the former absence of a production gRPC collector has been resolved; the historical package must not be reinterpreted as current approval.

The byte/depth cases were separated into `FS-DATA-WRITE-LIMITS-02`. Its [original production result](../../spec/compatibility/broad-runs/fs-write-limits-02-40dfc0da3-production-result.json) and [repaired saved-reference comparison](../../spec/compatibility/broad-runs/fs-write-limits-02-8b33aac4d-saved-result.json) remain independent evidence. That single-iteration owner permission is consumed and does not authorize this stream campaign. Those conditions are not scheduled for another observation.

## Current, next and backlog

| Queue position | Campaign | Remaining boundary |
| --- | --- | --- |
| CURRENT | Write stream / transaction precedence at `dee737c14` | `PROD_COMPLETE`; acquisition independently validated, diagnostic repair and saved-reference comparison pending. The original permission is consumed. |
| NEXT | `FS-DATA-WRITE-COMMIT-TRANSFORMS-03` | Canonical 500/501 transform compiler, local collector, comparator, Gate and fixed wire are reviewed. Outer permission, metadata, shared reservation and immutable acquisition integration remains preparation work. |
| BACKLOG | Transaction SDK retry / retention | Separate pinned SDK and bounded time campaigns; no automatic reuse of current permission. |
| BACKLOG | Remaining declared request / operation / catalog limits | Reuse eligible saved receipts before defining any new observation. Queue position does not waive parent scope. |

## Frozen stream scope and proposed bounds

The stream case creates only nonce-scoped owned documents. It includes an uncontended control, a read-write transaction holding a document lock, a contended multiwrite stream, refusal post-state checks, rollback, and a post-rollback stream control. Complete typed responses and the transaction lifecycle are retained. No index, Rules, database, Auth configuration or account creation is included.

The owner-approved envelope targets `fireemu-35fe6/(default)` with one in-flight request, at most three owned documents, at most 35 charged calls, a 1200-second total envelope, and a US$1.3035 planning ceiling. The 35 slots comprise two bounded OAuth preparation calls, eight metadata calls, and up to 25 data calls. The approved execution window is one iteration within 24 hours after approval, without automatic reobservation. This paragraph is not permission or a substitute for the frozen machine-readable manifest.

The cost reserve includes the pinned SDK's encoded receive ceiling; the smaller application-level decoded cap is not treated as a network-byte bound. The reserve is a conservative planning ceiling, not a measured invoice. Credential preparation is charged before sending, uses fixed endpoints and private worker input, and does not silently acquire replacement credentials after a rejection.

Five shared READ locks cover indexes, Rules, database configuration, Auth configuration and API-key binding; the owned document namespace has its own EXCLUSIVE lock. Unrelated non-conflicting namespaces can be scheduled independently. The frozen permission, manifest and shared reservation must agree on these scopes and the global budget.

## Retained local evidence and review

The combined owned local rehearsal at `dee737c14` used retained runtime artifact SHA-256 `be2771b9f2093cced55e8158d8d5a72ed35e6ac5e32edddb068daa45511e12ae`. The runtime artifact was built from source `cce4a4f9b`; `dee737c14` identifies the collector, not a rebuild of the runtime artifact. The local receipt SHA-256 is `a9b7bf52feeb728ec428fad5b6c8e8ff3c2b10041201308994380457d8ea085e`; collector source digest is `b052ce31b57e491e0d480f0dd34d3bcf797de99b57f2129970c2878bd258b383`.

The rehearsal completed 33 calls: two synthetic credential-preparation calls, eight metadata calls and 23 data calls. Final rollback and suffix deletion were unused conditional slots because rollback had already completed and the suffix was already proven absent. Typed cleanup, shared reservation release, child termination and listener shutdown were verified. Local self-comparison is not production parity, and synthetic OAuth responses are not production credential verification.

Independent review covered terminal ordering through the actual bridge/comparator and parent-side credential stopping through real child-process/socket/Gate/Ledger fixtures. Normal and same-callback ACK/status/end/close orders preserve successful receipts; real errors and missing responses remain incomplete. Complete gRPC codes 7 and 16 are recorded before credential failure stops subsequent grants, including recovery with that credential. Code 10 preserves the planned continuation. The integrated transport suite passed 20 tests; the bridge suite passed 33 with one explicit opt-in skip.

[Fixed-source inventory CI](https://github.com/t-k/fireemu/actions/runs/35227086496) completed successfully, including 1107 broad tests with 14 explicit skips and immutable historical checks. [Normal CI](https://github.com/t-k/fireemu/actions/runs/35227086566) separately passed formatting and all-target compilation. These results do not claim workspace test, formal verification, or production execution at this source.

## Execution and evidence gates

The owner explicitly approved the exact envelope, recorded at 2026-09-17T13:50:23Z with a conservative expiry of 2026-09-18T13:50:23Z. Fresh permission binding, nonce, final manifest digest and O7 admission were verified before O8 executed the single approved iteration. The additional general US$10 instruction does not expand this campaign's narrower approved bound. Expected configuration projections are historical baselines only; they must pass fresh, charged preflight checks within the approved envelope.

Cleanup requires this execution's ownership evidence, exact resource identity, current version and typed final absence. Ambiguous ownership, credential rejection, configuration drift or incomplete recording retains the journal and recovery responsibility; no unconditional deletion or automatic credential replacement is permitted. A failed final source/artifact binding remains failed during later comparison, even if files are subsequently restored.

The comparator distinguishes `MATCH`, `SEMANTIC_MISMATCH`, `INDETERMINATE` and `EXPECTED_NONDETERMINISM`. Complete unexpected semantics remain comparable; infrastructure, binding and cleanup failures are not semantic mismatches. A valid production receipt may be compared against a repaired local artifact without repeating production, but local success alone does not establish the receipt's acquisition validity or promote a parent.

## Production result and repair boundary

The approved iteration completed 33 requests (two OAuth preparation, eight metadata, 23 data) in approximately 63.48 seconds. Accounting reserved US$1.3035 and charged US$1.3033; this is not a measured invoice. Independent validation confirmed the frozen permission/source/artifact, charged journals, unchanged metadata, typed absence cleanup and released shared reservation. Two earlier local descriptor setup refusals occurred before any reservation or network request; their diagnostics remain preserved, and they did not create additional production iterations.

The original comparison is `SEMANTIC_MISMATCH`. Independent recomputation isolates GetDocument `NOT_FOUND` diagnostic wording and request-bound resource identities: production returned `Document "<owned-resource>" not found.`, while the retained local artifact returned `Document not found: <owned-resource>`. Codes, event order and document state do not differ in this finite case. The original receipt and v1 comparison remain immutable. Runtime repair and separately versioned, narrow resource-identity normalization must continue to detect the pre-fix wording difference; neither may turn incomplete acquisition into a match. Verification uses the saved production receipt rather than another production observation.

## Saved-reference repair verification

Runtime source `567565bdd654cab00dbb84101edcc7bdc628e230` corrects the GetDocument diagnostic. Its retained artifact SHA-256 is `e792e0bc1947bbd227b3ee9778eca093cda94fbde767911dd6139a6cbfd90be4`. A new owned local rehearsal completed recording, typed cleanup and reservation release, with processes and listeners closed. Adapter regression passed 385 tests with one existing skip; both affected Quint models were regenerated and the selected Connect/evidence checks passed 23 tests without skips.

The separately versioned, independently reviewed comparator integrated at `6dff3192a6b8b23ea462730bfc105747849a7788` revalidates the fixed acquisition files, historical permission, charged journals, released ledger, original comparison and new artifact/build evidence. It normalizes only the exact request resource slot, retaining diagnostic grammar. The pre-fix saved pair remains `SEMANTIC_MISMATCH`; the repaired pair is `EXPECTED_NONDETERMINISM`. Integration passed 92 Node tests without skips and the actual saved-input authority test. No new production request was sent.

The immutable result summary is `spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result.json`. One finite diagnostic mismatch cluster is repaired. This does not close all Write/transaction conditions or promote either parent; `COMPAT_VERIFIED` remains 0/14.

## Integrated workspace verification

At fixed source `4658dc3b520728cc874453daddb78ca858e6f2fc`, `cargo nextest run --workspace --profile pr` completed with 2,623 passes, 14 slow tests and 81 skips in 103.504 seconds of test execution. The [ignored-test audit](ignored-test-audit-20260917.md) explains the separate verification obligations; a skip is not a pass. This run does not replace explicitly selected SDK or formal verification lanes.

[Normal CI](https://github.com/t-k/fireemu/actions/runs/35236075018) and [compatibility inventory CI](https://github.com/t-k/fireemu/actions/runs/35236074922) both completed successfully at that same source. Normal CI formatting and compilation are separate from the local workspace execution reported above. These checks add local regression evidence, with no new production observation or parent promotion.

## Commit transform acquisition and local proof

The independently reviewed Commit acquisition path is integrated at `09c02557e9a537208a7912f039edb23c1131b1fc`. It uses the shared Ledger and Coordinator, two fixed bounded OAuth requests, eight metadata reads and 17 data requests. It binds conditional creation and cleanup, immutable acquisition/release records, source/artifact inputs and credential-free saved comparison. Integration passed 142 campaign tests, the current Explain binding test, Ruff and formatting. The fixed-source broad suite passed 1,193 tests with 14 explicit skips. This is infrastructure/local verification, not a Commit production observation.

The owned local runner now provides an explicit reviewed artifact profile rather than transient constant overrides. At runner source `a09ccc5e3ab36a90a7f8d2ddd4856340fd82f255`, the checked-in CLI used the original retained `567565bdd` build manifest and artifact `e792e0bc1947bbd227b3ee9778eca093cda94fbde767911dd6139a6cbfd90be4`. The copied manifest is bound before child I/O and rechecked at completion. Independent review reproduced 11 observation rows plus six cleanup rows: Commit500 succeeded, Commit501 was refused without changing the prior state, and both resources were conditionally deleted with typed final absence. The local self-contract is MATCH; acquisition and promotion remain false. Evidence SHA-256 is `915ec79ce63c9c02d243afb3c7d76d59992ff127ee26abcebbdbbfd9879b558c`; result SHA-256 is `6899f0b8b3c41c32902db647406fbb549453754dd3a97745705601612337a780`. Owned processes and temporary artifact copies were removed; the original retained artifact remains available.

The earlier local run at collector `4658dc3b5` used a transient parent adapter whose source was not retained. Its original records remain unchanged and are not retroactively upgraded; the new checked-in invocation supplies the replacement reproducible local proof. The reviewed profile implementation is integrated at `7043d396c`. A separately reviewed launch invocation, canonical shared Ledger selection, fresh owner/credential bindings and O7 admission still precede production execution.

Request-byte preparation is integrated separately at `e615ba33c`. It creates three disjoint conditional-create probes with exact raw REST body lengths at 10 MiB minus one, exactly 10 MiB and plus one. It validates actual wire operations, logical field snapshots and cleanup-before-next-probe scheduling. The 33 offline tests and independent review cover the compiler only; a collector and actual local shadow remain required. Raw HTTP body length is still an observation hypothesis, not an established backend enforcement metric or gRPC claim. No parent is promoted by these preparation changes.

## Per-row counts for the saved-reference comparison

The saved result `spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result.json` records only whole-comparison verdicts, so a reviewer cannot see how much of the finite journal actually agreed. The row counts are now published separately in `spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result-rows.json`. Both files are immutable; the new one adds counts and changes no classification rule.

A row is one data RPC, enumerated in the order the comparator ticks its finite RPC budget: fifteen phase RPCs, then eight cleanup RPCs. Both receipts record 23 data requests, and the enumeration is checked against that recorded count. Positive agreement is the number of rows whose normalized semantic content is equal, that is `MATCH` plus `EXPECTED_NONDETERMINISM`.

The original comparison agrees on 15 of 23 rows. The eight differing rows are exactly the code-5 `GetDocument` absence reads: both create preflights, the suffix preflight, the contention suffix readback, and the four cleanup absence reads. This is the recorded difference cluster, now localized rather than asserted. The repaired comparison agrees on 23 of 23 rows, with no semantic mismatch and no indeterminate row. No row is `MATCH`, because project, document prefix, owner, stream tokens and timestamps differ between a production run and an owned local run by construction.

The counts are derived from the comparator at `6dff3192a6b8b23ea462730bfc105747849a7788`, whose bytes on disk are identical to the SHA-256 the frozen preparation inputs bind. The retained production receipt, prepared inputs and repaired local receipt are verified against the digests the campaign recorded, and the retained `567565bdd` artifact is present at its recorded SHA-256. Nothing was rebuilt, re-executed or bound to the current HEAD, and no production request was sent. The generator is not acquisition authority; `tools/compat-broad/fs-write-txn-recompare-v2` remains the only entry that can validate acquisition.
