# Blocking function on the creating request (revision 2): scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Ten-case frame (eight executed rows, two conditionally skipped rows) projected without secrets from the saved 2026-09-12 production run of auth-blocking-create-disable revision 2 with a first-generation beforeSignIn function that answers disabled: true for an email-prefix selector. Approved as recorded: the creating sign-up is refused with USER_DISABLED, the created record exists and is disabled, a second sign-up with the same email is EMAIL_EXISTS, the control signs up and signs in and its sign-up photo URL is not persisted, the function was removed and the trigger registration restored with a digest comparison, and both accounts were deleted with absence confirmation. The two token rows were skipped because the sign-up was refused and are not approved as executed. One function shape, no tenant, a single run; not extended to other auto-creating sign-in methods, beforeCreate, SDK or Rules.

Subject: `206490130d5191df9a25a80634315a2b2c0ba190860cc91f7455931a9c25b362`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `3cadafe7a42effb58b392897298e583a32e51792`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving a recorded observation does not authorize new production operations.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| control-c-signup | control | accepted / none |
| control-c-signup-readback | control | accepted / none |
| control-c-signin | control | accepted / none |
| target-t-signup | diagnostic | refused / USER_DISABLED |
| target-t-token-lookup | diagnostic | skipped / none |
| target-t-token-refresh | diagnostic | skipped / none |
| target-t-record-readback | control | accepted / none |
| target-t-signin | diagnostic | refused / USER_DISABLED |
| target-t-second-signup | diagnostic | refused / EMAIL_EXISTS |
| control-c-final-signin | control | accepted / none |

[Approval record](../../spec/compatibility/evidence/auth-blocking-create-disable/approval.json) · [Record](../../spec/compatibility/evidence/auth-blocking-create-disable/receipt.json) · [Candidate page](auth-blocking-create-disable.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private run, earlier candidates in history, the source mapping and every earlier approval remain unchanged.
