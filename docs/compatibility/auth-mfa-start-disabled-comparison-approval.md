# mfaSignIn:start on a disabled account, local comparison: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Row-by-row comparison of the approved production record of auth-mfa-start-disabled with one run of the same corpus on an owned local fireemu artifact built after mfa_sign_in_start stopped refusing a disabled account (strict profile, artifact, runtime inputs and recorder files all bound to one commit). All six semantic projections agree, including mfaSignIn:start accepted on the disabled account and refused at finalize. Approved as a comparison of these cases on that artifact, profile and recorder; the pre-fix mismatch comparison stays in history. Not a production run and not a claim beyond these six cases.

Subject: `07636ce70c9c46289b4e49d64b4f09fcae997901e1bcc89771e4ead3e7968353`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `aef95ad3e6f623d6ce8263f52ce20791b67afe68`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Compared case | Same semantic projection |
| --- | --- |
| baseline-fresh-finalize | True |
| disabled-start | True |
| disabled-finalize | True |
| reenabled-start | True |
| reenabled-finalize | True |
| final-fresh-finalize | True |

All six rows agree on the corrected artifact: mfaSignIn:start on a disabled account is accepted and refused at finalize, and the held pending survives re-enablement, matching the approved production record. Approved as a comparison of these cases on that artifact, profile and recorder.

[Approval record](../../spec/compatibility/evidence/auth-mfa-start-disabled/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-mfa-start-disabled/local-comparison.json) · [Comparison page](auth-mfa-start-disabled-comparison.md).

The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, the pre-fix mismatch comparison in history, the source mapping and every earlier approval remain unchanged.
