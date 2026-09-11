# Blocking function on the creating request (revision 2), local comparison: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Row-by-row comparison of the approved production record of auth-blocking-create-disable revision 2 with one run of the same corpus on the owned local artifact: all ten semantic projections agree (creating sign-up refused, disabled record kept, second sign-up EMAIL_EXISTS, photo URL not persisted). Production used the recorded first-generation blocking function; the owned local run used the equivalent second-generation Identity fixture installed with npm ci from the committed lockfile, with the runner, fixture files, lockfile and artifact bound to committed content. Approved as a comparison of these cases on that artifact, profile and recorder; not a claim of Functions SDK generation parity or beyond these cases.

Subject: `8d21beb022a6afb5f1bb22aa9d164f9e6a16a469f6fa7379d1e3b5fcb4c8fd9e`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `bfe70d7f1bb8d95d1f4a49abfc2f3c09a4da0122`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Compared case | Same semantic projection |
| --- | --- |
| control-c-signup | True |
| control-c-signup-readback | True |
| control-c-signin | True |
| target-t-signup | True |
| target-t-token-lookup | True |
| target-t-token-refresh | True |
| target-t-record-readback | True |
| target-t-signin | True |
| target-t-second-signup | True |
| control-c-final-signin | True |

[Approval record](../../spec/compatibility/evidence/auth-blocking-create-disable/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-blocking-create-disable/local-comparison.json) · [Comparison page](auth-blocking-create-disable-comparison.md).

The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private runs, earlier records in history, the source mappings and every earlier approval remain unchanged.
