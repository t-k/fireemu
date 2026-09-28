# Blocking function that disables the account, local comparison: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Row-by-row comparison of the approved production record of auth-blocking-disable revision 1 with one run of the same corpus on the owned local artifact built after fireemu stopped persisting a hook disable for an existing account's first-factor sign-in: all twelve semantic projections agree, including the immediate readback of the flag that differed on the uncorrected artifact (that earlier comparison stays in history at commit 98be375). Production used the recorded first-generation blocking function; the owned local run used the equivalent second-generation Identity fixture installed with npm ci from the committed lockfile, with the runner, fixture files, lockfile and artifact bound to committed content. Approved as a comparison of these cases on that artifact, profile and recorder; not a claim of Functions SDK generation parity or beyond these cases.

Subject: `6c130b97db655709ced0357d700314f9be1bce8a7099dfeb18ceeed51b86ae08`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `bfe70d7f1bb8d95d1f4a49abfc2f3c09a4da0122`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Compared case | Same semantic projection |
| --- | --- |
| baseline-b-fresh-finalize | True |
| hook-c-first-signin | True |
| hook-c-token-lookup | True |
| hook-c-token-refresh | True |
| hook-c-disabled-readback | True |
| hook-c-second-signin | True |
| hook-a-first-finalize | True |
| hook-a-token-lookup | True |
| hook-a-token-refresh | True |
| hook-a-disabled-readback | True |
| hook-a-second-signin | True |
| final-b-fresh-finalize | True |

[Approval record](../../spec/compatibility/evidence/auth-blocking-disable/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-blocking-disable/local-comparison.json) · [Comparison page](auth-blocking-disable-comparison.md).

The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, earlier records in history, the source mappings and every earlier approval remain unchanged.
