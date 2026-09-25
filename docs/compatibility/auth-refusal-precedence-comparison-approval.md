# Precedence of overlapping refusals, local comparison: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Row-by-row comparison of the approved production record of auth-refusal-precedence revision 1 with one run of the same corpus on an owned local fireemu artifact built after the end-user accounts:update route was corrected to authenticate before authorizing administrator-only fields (strict profile, --only auth, no configuration change, codes read from the emulator inspection route; artifact, runtime inputs and recorder files all bound to commit c3a7973b). All nine semantic projections agree, including the tampered-token update now refused INVALID_ID_TOKEN. Approved as a comparison of these cases on that artifact, profile and recorder; not a production run, and not a claim that the local artifact matches on anything outside these nine cases or that the non-tampered session-failure orderings are production-observed.

Subject: `81b71859a84bb7aa08dc8312b1fbf59c94d62e6a1e3eb8d1c71609b2f4e5f2f1`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `c3a7973b31274311ac64835aec761e0bb2a4c1e9`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Compared case | Same semantic projection |
| --- | --- |
| baseline-a-fresh-finalize | True |
| baseline-b-fresh-finalize | True |
| invalid-token-admin-field-update | True |
| disabled-a-wrong-code-finalize | True |
| disabled-b-correct-code-finalize | True |
| reenabled-a-held-finalize | True |
| reenabled-b-held-finalize | True |
| final-a-fresh-finalize | True |
| final-b-fresh-finalize | True |

[Approval record](../../spec/compatibility/evidence/auth-refusal-precedence/comparison-approval.json) · [Comparison record](../../spec/compatibility/evidence/auth-refusal-precedence/local-comparison.json) · [Comparison page](auth-refusal-precedence-comparison.md).

The comparison page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these nine cases. The private runs, the discarded run 1, the source mapping and every earlier approval remain unchanged.
