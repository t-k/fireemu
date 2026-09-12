# Held MFA pending credential across admin-password-update, local comparison: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Row-by-row comparison of the approved production record of the admin-password-update trigger with one run of the same corpus on an owned local fireemu artifact (strict profile, artifact, runtime inputs and recorder files all bound to one commit). All seven semantic projections agree. Approved as a comparison of these cases on that artifact, profile and recorder; not a production run, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger.

Subject: `01f2856570a79bfbce44db3cfcd6c12939002b2c10856c2e84a8f2aac3a4b6d7`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `f4b7f579e63c75290fd68a7bb9b8a1caebf29d61`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Compared case | Same semantic projection |
| --- | --- |
| baseline-fresh-finalize | True |
| trigger | True |
| held-start | True |
| held-finalize | True |
| held-lookup | True |
| held-refresh | True |
| final-fresh-finalize | True |

[Approval record](../../spec/compatibility/evidence/auth-pending-trigger-admin-password-update/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-admin-password-update/local-comparison.json) · [Comparison page](auth-pending-trigger-admin-password-update-comparison.md).

The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, the source mapping and every earlier approval remain unchanged.
