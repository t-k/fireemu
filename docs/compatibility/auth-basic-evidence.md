# Bounded Auth basic observations

Status: candidate observations, not approved. No feature-level execution approval is recorded by this page.

Scope: email/password REST, default project (no tenant), local fireemu strict, and production with password sign-in and improved email privacy enabled. Exact Admin lookup is used only for ownership and cleanup. This does not attest SDK, MFA, OOB, Rules, public npm, or complete Auth compatibility.

These are allowlisted semantic projections, not raw responses. Credentials and raw account data were not retained. Offline checks verify projection consistency and recorder inputs; they cannot independently recompute the observations from raw responses or verify token signatures. The owned-process assertion is recorder-reported; its detailed private receipt is hash-bound, not publicly reproduced.

| Case | Local | Production |
|---|---|---|
| signup | Matched | Matched |
| signin | Matched | Matched |
| lookup | Matched | Matched |
| wrong-password | Matched | Matched |
| unchanged-state | Matched | Matched |
| refresh | Matched | Matched |
| refreshed-lookup | Matched | Matched |
| delete | Matched | Matched |
| deleted-account-absent | Matched | Matched |

Local: 9/9 matched at `2026-09-10T02:39:46.623986+00:00`. Exact UID and email absence confirmed. Recorder source: `c8fcdb0351c1622d3b73ea4009f2d288c3f1833a`. Configuration digest: `dc4466f0080ac58a25e2df92b765d1d666052fef735e94f4fe697a2a2507ada4`.

Production: 9/9 matched at `2026-09-10T02:39:44.313470+00:00`. Exact UID and email absence confirmed. Recorder source: `c8fcdb0351c1622d3b73ea4009f2d288c3f1833a`. Configuration digest: `901acc9e8fad556673061056698b04d9fa544e539fab4bbb6b4f8b3bd4fdcbdf`.

Local artifact SHA-256: `5cd95e3759e62b55d4b1de47425ce94031e48d8e45c365ec2a2a0d6285db2a77`. Runtime source: `c8fcdb0351c1622d3b73ea4009f2d288c3f1833a`. The owned process exited and its Auth/control listeners closed.

[Machine-readable projections](../../spec/compatibility/evidence/auth-basic/observations.json) · [Recorder, safety constraints and recovery](../../tools/auth-basic/README.md). Existing aggregation approvals remain separate. Source-section review, requirement mapping and human approval for this Auth slice remain pending.
