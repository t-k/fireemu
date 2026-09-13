# Compatibility inventory merge acceptance

This table fixes the scope of the `feat/compatibility-inventory` pull request. It does not claim complete Firebase compatibility. Production observations, saved-production comparisons, local invariants, SDK runs and direct/mapped local comparisons remain separate evidence classes.

| Class | Acceptance item | Required state for this pull request |
| --- | --- | --- |
| A | Compatibility inventory and evidence integrity | Requirement, capability, gap and generated inventory references pass their existing gates. Historical observations and approvals remain immutable, and regenerated Quint evidence is produced only by the repository generator. |
| A | Identity Platform compatibility fixes in this branch | The implemented account update, credential lifecycle, project/tenant binding, MFA boundary and error-shape fixes retain their scoped regression coverage. Unobserved combinations remain explicit. |
| A | Firestore compatibility fixes in this branch | The implemented write/query/transaction, atomicity, snapshot, stream, cancellation and post-state conditions retain their scoped regression coverage. Standard and Enterprise claims remain distinct. |
| A | Finite Enterprise Pipeline execution | Local latest-read execution remains limited to collection with the documented optional equality, projection, offset and limit stages. Paging, snapshot, cancellation, refusal and post-state controls pass; other stages and production parity remain excluded. |
| A | Observation and comparison safety | Existing admissions keep fixed manifests, typed inputs, budgets, ownership journals, recovery reservations and evidence-class separation. No credential, API key, private journal or raw secret is tracked. |
| A | Main integration and delivery | The feature is combined with the recorded current `origin/main`, required local gates and relevant saved-reference regressions are recorded against one candidate, blocking independent-review findings are resolved, and a Draft PR targets `main`. |
| B | Complete product denominator and release attestation | The inventory remains an incomplete source-tree inventory with zero accepted feature execution receipts. Complete API/source enumeration, release snapshots and upstream monitoring remain follow-up work. |
| B | Deferred Auth investigations | Revision 3, GAP-AUTH-007, AUTH-U03, signed/strict custom-token combinations, external IdP and unobserved tenant/error-priority combinations remain separate work unless a merge regression requires a fix. |
| B | Deferred Firestore and SDK coverage | G2 production transaction questions, remaining Enterprise stages, MongoDB, browser/WebChannel, broader Rules/SDK/Listen behavior, production error ordering and performance/RSS qualification remain outside this pull request. |
| B | Additional production observations | No new production authentication, read or data operation is part of merge preparation. Existing saved observations retain their original artifact, contract and limitation. |
| C | Prepared G0 two-scenario observation | The fixed `a35f85b4` checkout and bound execution package remain `waiting-owner`. The owner must either accept this observation as follow-up for this merge or separately provide identity, permission window, fresh nonce, settings/pricing acceptance and recovery owner for the exact fixed run. |
| C | Final acceptance and merge | A human reviews and accepts the final base/head, unresolved limitations and G0 disposition, then decides whether to merge. This branch does not enable auto-merge, push `main`, tag or release. |

New feature stages and adjacent cases do not enter class A unless they close a regression, security defect, review blocker or missing verification required by an item above.

## Fixed merge candidate

The [local merge-readiness result](../../spec/compatibility/broad-runs/2f0de271-merge-ready-local.json) binds the technical candidate `2f0de271f474d83d8521dc5d6c80f6cc12fa2009` to base `d987d5ddcc1374cee425f08d6d81915795fc2ab5`. It records the workspace, formal, compatibility, SDK, UI and distribution checks without treating local execution as production evidence.

The immutable first46 reference still compares as46 matches. The last correctly bound second45 saved-reference comparison remains45 matches at `37e4c396`; a fresh local second45 run completed and cleaned up, but pairing it with the older production record is indeterminate because their observer digests differ. The comparator rejected that pair, and the older32/13 production result and repaired45/45 result remain unchanged.

Technical merge preparation is complete with the final test-harness adjustment independently approved; hosted CI remains to be recorded on the publication head. G0 remains a separate owner decision at fixed `a35f85b4`; no new production operation occurred during merge preparation.
