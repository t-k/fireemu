# Compatibility inventory merge acceptance

This table fixes the scope of the `feat/compatibility-inventory` pull request. It does not claim complete Firebase compatibility. Production observations, saved-production comparisons, local invariants, SDK runs and direct/mapped local comparisons remain separate evidence classes.

| Class | Acceptance item | Required state for this pull request |
| --- | --- | --- |
| A | Compatibility inventory and evidence integrity | Requirement, capability, gap and generated inventory references pass their existing gates. Historical observations and approvals remain immutable, and regenerated Quint evidence is produced only by the repository generator. |
| A | Identity Platform compatibility fixes in this branch | The implemented account update, credential lifecycle, project/tenant binding, MFA boundary and error-shape fixes retain their scoped regression coverage. Unobserved combinations remain explicit. |
| A | Firestore compatibility fixes in this branch | The implemented write/query/transaction, atomicity, snapshot, stream, cancellation and post-state conditions retain their scoped regression coverage. Standard and Enterprise claims remain distinct. |
| A | Finite Enterprise Pipeline execution | Local latest-read execution remains limited to collection with the documented optional equality, projection, offset and limit stages. Paging, snapshot, cancellation, refusal and post-state controls pass; other stages and production parity remain excluded. |
| A | Observation and comparison safety | Existing admissions keep fixed manifests, typed inputs, budgets, ownership journals, recovery reservations and evidence-class separation. No credential, API key, private journal or raw secret is tracked. |
| A | Prepared G0 two-scenario observation | The fixed `a35f85b4` checkout ran its two scenarios once under the separately recorded permission. Recording, state verification and cleanup completed. The original 10-match/2-mismatch result and the repaired-runtime 12/12 saved-reference comparison both remain available as candidate evidence. |
| A | Main integration and delivery | The feature is combined with the recorded current `origin/main`, required local gates and relevant saved-reference regressions are recorded against one candidate, blocking independent-review findings are resolved, and a Draft PR targets `main`. |
| B | Complete product denominator and release attestation | The inventory remains an incomplete source-tree inventory. The single authorized G0 candidate does not establish a complete API/source denominator, release snapshot or upstream monitoring; those remain follow-up work. |
| B | Deferred Auth investigations | Revision 3, GAP-AUTH-007, AUTH-U03, signed/strict custom-token combinations, external IdP and unobserved tenant/error-priority combinations remain separate work unless a merge regression requires a fix. |
| B | Deferred Firestore and SDK coverage | G2 production transaction questions, remaining Enterprise stages, MongoDB, browser/WebChannel, broader Rules/SDK/Listen behavior, production error ordering and performance/RSS qualification remain outside this pull request. |
| B | Additional production observations | The authorized G0 run is the only new production operation in final merge preparation. All other saved observations retain their original artifact, contract and limitation; no additional observation is required by this pull request. |
| C | Final acceptance and merge | A human reviews and accepts the final base/head, evidence boundaries and unresolved limitations, then decides whether to merge. This branch does not enable auto-merge, push `main`, tag or release. |

New feature stages and adjacent cases do not enter class A unless they close a regression, security defect, review blocker or missing verification required by an item above.

## Fixed merge candidate

The [final merge-readiness result](../../spec/compatibility/broad-runs/feac4c51-merge-ready-local.json) binds the technical candidate `feac4c5141482fe30ff5ed9b57c3033e1f505913` to base `d987d5ddcc1374cee425f08d6d81915795fc2ab5`. It records the workspace, formal, compatibility, SDK, UI, distribution and scoped G0 evidence without treating local execution as production evidence or the candidate observation as result approval. The earlier [local candidate](../../spec/compatibility/broad-runs/b33a150c-merge-ready-local.json) remains unchanged.

The immutable first46 reference still compares as 46 matches. The last correctly bound second45 saved-reference comparison remains 45 matches at `37e4c396`; a fresh local second45 run completed and cleaned up, but pairing it with the older production record is indeterminate because their observer digests differ. The comparator rejected that pair, and the older 32/13 production result and repaired 45/45 result remain unchanged.

The fixed G0 run completed at `a35f85b4` with configuration unchanged and all four owned documents confirmed absent. Its 12 observation rows originally produced 10 matches and two mismatches; the scoped runtime correction later compares all 12 saved responses without another production operation. The observation remains candidate evidence.

Technical merge preparation is complete. The final cross-platform CI fixes, including loopback endpoint normalization, race-free fixture shutdown and production-aligned runner handshake allowances, have independent correctness and security approval. Pull-request CI, compatibility inventory and Functions SDK discovery have passed at the fixed technical source. Full CI, Quint and conformance are the remaining hosted confirmations before the candidate can be handed to human final review and merge judgment.
