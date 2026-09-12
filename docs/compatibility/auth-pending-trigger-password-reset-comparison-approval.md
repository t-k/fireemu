# Held MFA pending credential across password-reset, local comparison: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Row-by-row comparison of the approved production record of the password-reset trigger with one run of the same corpus on an owned local fireemu artifact (strict profile, artifact, runtime inputs and recorder files all bound to one commit). All seven semantic projections agree. Approved as a comparison of these cases on that artifact, profile and recorder; not a production run, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger.

Subject: `31673c1f5a5e3846b4f2e7c270e5f12bc99a536dffa816ad63285251d81ca1b2`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `35929c23acdf395cf679672da9cbf16199d8c8b4`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

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

[Approval record](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/local-comparison.json) · [Comparison page](auth-pending-trigger-password-reset-comparison.md).

The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, the source mapping and every earlier approval remain unchanged.
