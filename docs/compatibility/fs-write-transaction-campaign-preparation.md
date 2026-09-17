# Firestore Write and transaction campaign preparation

## Current execution boundary

The Write/transaction campaign now has a bounded gRPC transport, shared Gate and Ledger admission, metadata coordinator, immutable acquisition receipt, and credential-free comparator. The reviewed execution source is `dee737c14e68eb4f546b7ca4c827871fc48a2503`. This is a prepared campaign with completed local rehearsal, not a production observation. The owner approved the bounded envelope on 2026-09-17; final fresh binding and O7 admission remain mandatory before execution. `FS-DATA-WRITE` and `FS-TRANSACTION` remain below `COMPAT_VERIFIED`.

The earlier combined [`v9 package`](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9.json), [binding](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9-binding.json), and [local plan](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v9-local-shadow.json) are historical preparation artifacts. Their bytes, earlier versions, source identities, and budgets remain unchanged. They are not the current executable stream envelope. In particular, the former absence of a production gRPC collector has been resolved; the historical package must not be reinterpreted as current approval.

The byte/depth cases were separated into `FS-DATA-WRITE-LIMITS-02`. Its [original production result](../../spec/compatibility/broad-runs/fs-write-limits-02-40dfc0da3-production-result.json) and [repaired saved-reference comparison](../../spec/compatibility/broad-runs/fs-write-limits-02-8b33aac4d-saved-result.json) remain independent evidence. That single-iteration owner permission is consumed and does not authorize this stream campaign. Those conditions are not scheduled for another observation.

## Current, next and backlog

| Queue position | Campaign | Remaining boundary |
| --- | --- | --- |
| CURRENT | Write stream / transaction precedence at `dee737c14` | Owner approved the concrete envelope on 2026-09-17. Fresh permission, nonce and manifest binding are being finalized for O7 admission, followed by charged environment checks before execution. |
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

The owner explicitly approved the exact envelope, recorded at 2026-09-17T13:50:23Z with a conservative expiry of 2026-09-18T13:50:23Z. Fresh permission binding, nonce, final manifest digest and O7 admission are still required before O8 may perform any OAuth or production request. The additional general US$10 instruction does not expand this campaign's narrower approved bound. Expected configuration projections are historical baselines only; they must pass fresh, charged preflight checks within the approved envelope.

Cleanup requires this execution's ownership evidence, exact resource identity, current version and typed final absence. Ambiguous ownership, credential rejection, configuration drift or incomplete recording retains the journal and recovery responsibility; no unconditional deletion or automatic credential replacement is permitted. A failed final source/artifact binding remains failed during later comparison, even if files are subsequently restored.

The comparator distinguishes `MATCH`, `SEMANTIC_MISMATCH`, `INDETERMINATE` and `EXPECTED_NONDETERMINISM`. Complete unexpected semantics remain comparable; infrastructure, binding and cleanup failures are not semantic mismatches. A valid production receipt may be compared against a repaired local artifact without repeating production, but local success alone does not establish the receipt's acquisition validity or promote a parent.
