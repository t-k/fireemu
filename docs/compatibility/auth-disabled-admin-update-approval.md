# Administrative updates to a disabled account: scoped human approval

Verified and approved within this limited scope. This is not a new production run and not a claim of complete Auth compatibility.

Ten-case frame (eight executed rows, two conditionally skipped rows) projected without secrets from the saved 2026-09-12 production run of auth-disabled-admin-update revision 1. Approved as recorded: an administrative password replacement and a photo update of a disabled account are accepted and applied with no tokens returned, the account's own sign-in stays USER_DISABLED, the replaced password signs in after re-enablement, the control signs in at every phase, the configuration and password policy are unchanged, and both accounts are deleted with absence confirmation. The two token rows were skipped because no tokens were returned and are not approved as executed. No tenant, two update fields, a single run; not extended to other fields, self-service updates, SDK or Rules.

Subject: `c5edbe9850fc52c66c666ca0c62961af3c4ad214fc074a950380c592960560fd`. Recomputed from the complete record; this approval cannot transfer to a changed subject.

Reviewed commit: `3cadafe7a42effb58b392897298e583a32e51792`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving a recorded observation does not authorize new production operations.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| baseline-a-signin | control | accepted / none |
| baseline-b-signin | control | accepted / none |
| disabled-a-password-update | diagnostic | accepted / none |
| disabled-a-update-token-lookup | diagnostic | skipped / none |
| disabled-a-update-token-refresh | diagnostic | skipped / none |
| disabled-a-photo-update | diagnostic | accepted / none |
| disabled-a-signin | diagnostic | refused / USER_DISABLED |
| disabled-b-signin | control | accepted / none |
| reenabled-a-signin | diagnostic | accepted / none |
| reenabled-b-signin | control | accepted / none |

[Approval record](../../spec/compatibility/evidence/auth-disabled-admin-update/approval.json) · [Record](../../spec/compatibility/evidence/auth-disabled-admin-update/receipt.json) · [Candidate page](auth-disabled-admin-update.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these cases. The private run, earlier candidates in history, the source mapping and every earlier approval remain unchanged.
