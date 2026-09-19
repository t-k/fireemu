# Hook-applied disable, readback timing: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Eleven executed rows projected without secrets from the saved 2026-09-12 production run of auth-blocking-readback revision 1 with the recorded first-generation disabling function. Approved as recorded: two claimed accounts were refused on sign-in; the disabled flag read back as not disabled before, immediately after, five and about thirty-one seconds after the refusal for one account, and after thirty seconds with no earlier read for the other, while their second sign-ins were refused under the registered function; the control signed in first and last; the function was removed and the trigger registration restored with a digest comparison; the three accounts were deleted with absence confirmation. The measured seconds are recorder-side. Not extended to the same accounts after the function's removal, to propagation timing beyond these points, to other sign-in methods, or to SDK or Rules.

Subject: `81dae6d26f525a31e121abb87669e875026696f50ce44a223fc9c396c9806b9b`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `3cadafe7a42effb58b392897298e583a32e51792`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving a recorded observation does not authorize new production operations.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| control-z-signin | control | accepted / none |
| x-readback-before | control | accepted / none |
| x-first-signin | diagnostic | refused / USER_DISABLED |
| x-readback-immediate | control | accepted / none |
| x-readback-after-5s | control | accepted / none |
| x-readback-after-30s | control | accepted / none |
| x-second-signin | diagnostic | refused / USER_DISABLED |
| y-first-signin | diagnostic | refused / USER_DISABLED |
| y-readback-after-30s-unread | control | accepted / none |
| y-second-signin | diagnostic | refused / USER_DISABLED |
| control-z-final-signin | control | accepted / none |

[Approval record](../../spec/compatibility/evidence/auth-blocking-readback/approval.json) · [Record](../../spec/compatibility/evidence/auth-blocking-readback/receipt.json) · [Candidate page](auth-blocking-readback.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private run, earlier candidates in history, the source mapping and every earlier approval remain unchanged.
