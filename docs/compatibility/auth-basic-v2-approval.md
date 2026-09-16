# Auth basic revision 2: scoped human approval

Twelve scoped cases verified and approved as redacted semantic observations matching the published checks. This is not approval of Auth as a whole.

Email/password Auth REST using end-user tokens; no tenant; local strict profile and recorded production configuration; only the recorded artifact, configuration and corpus revision 2 twelve cases; approved as redacted semantic observations matching the published checks.

Subject: `0eb3689e1eb636f4166d3f296bba2fea2cf2ac70bf6ab6901d1077575a2a60cb`. Recomputed from the complete receipt during offline validation; approval cannot transfer to a changed subject.

Reviewed commit: `29378b6f25fdad1e44e08114f5b684aeff4de808`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This repository records the user's explicit approval; it is not a cryptographic signature or independent reviewer authentication mechanism.

| Approved case | Local | Production |
|---|---|---|
| signup | Matched | Matched |
| signup-token-lookup | Matched | Matched |
| signup-token-refresh | Matched | Matched |
| signup-refreshed-lookup | Matched | Matched |
| signin | Matched | Matched |
| lookup | Matched | Matched |
| wrong-password | Matched | Matched |
| unchanged-state | Matched | Matched |
| refresh | Matched | Matched |
| refreshed-lookup | Matched | Matched |
| delete | Matched | Matched |
| deleted-account-absent | Matched | Matched |

Signup and signin tokens are used for account lookup and refresh; refreshed tokens are used for lookup, and the signin refresh flow supplies the deletion token. Admin APIs support dedicated-account ownership verification and cleanup, not an Admin-only authentication claim. Wrong-password refusal is conditional on the recorded improved email privacy configuration.

Expired-token refusal and independent token signature validation remain unverified. Returned expiry is 3600 seconds in the four token-returning cases; this does not establish rejection after time elapses. SDK, MFA, Rules, OOB, tenant behavior, public npm artifacts and complete Auth compatibility are outside this approval.

[Approval record](../../spec/compatibility/evidence/auth-basic-v2/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-basic-v2/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-basic-v2/source-review.json). Token values and passwords are not published, so third parties cannot independently replay token checks from these records.

The [original candidate page](auth-basic-v2.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Original nine-case observations and aggregation approvals remain unchanged; broad feature labels are not promoted.
