# Auth password change: scoped human approval

Twelve scoped cases verified and approved as redacted semantic observations matching the published checks. This is not approval of Auth as a whole.

Password change through REST using fresh end-user tokens; no tenant; local strict profile and recorded production authentication/password-policy configuration; only the recorded artifact, configuration and auth-password corpus revision 1 twelve cases; approved as redacted semantic observations matching the published checks.

Subject: `aaa9cf7bd198aa7ca6c9215718323539c50ff339d02ab0392f8d26ba85eaa9fb`. Recomputed from the complete receipt during offline validation; approval cannot transfer to a changed subject.

Reviewed commit: `af96e971d500c132a57a2a0ef44e7eebaf61795f`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This repository records the user's explicit approval; it is not a cryptographic signature or independent reviewer authentication mechanism.

| Approved case | Local | Production |
|---|---|---|
| signup | Matched | Matched |
| baseline-signin | Matched | Matched |
| change-password | Matched | Matched |
| changed-token-lookup | Matched | Matched |
| old-password-rejected | Matched | Matched |
| unchanged-state | Matched | Matched |
| new-password-signin | Matched | Matched |
| new-password-lookup | Matched | Matched |
| changed-token-refresh | Matched | Matched |
| refreshed-lookup | Matched | Matched |
| delete | Matched | Matched |
| deleted-account-absent | Matched | Matched |

A successful baseline signin proves the original password and supplies the fresh ID token for accounts:update. Approval includes password replacement, HTTP400 INVALID_LOGIN_CREDENTIALS for old-password signin, new-password signin as the same UID/email, actual use of update-response ID and refresh tokens, selected-account-field preservation, and the recorded deletion/process-exit checks. Admin APIs establish dedicated-account ownership and cleanup, not an Admin-only password change.

Old-token revocation timing, expired-token rejection, recent-login time requirements, weak-password and policy-boundary rejection, password reset, SDK behavior, communication-loss or forced-termination recovery remain unverified by this slice. Recorded successful cleanup does not establish fault-recovery guarantees. Independent JWT verification, MFA, tenant behavior, Rules, public npm artifacts and full Auth compatibility are outside this approval.

[Approval record](../../spec/compatibility/evidence/auth-password/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-password/source-review.json). Passwords, tokens, password hashes and account identities are not published. Five token-returning cases distinguish positive-integer expiry from 3600-second agreement; immediate use does not prove elapsed expiry or old-token revocation. Private selected-field comparisons preserve missing/null/type distinctions and publish only comparison results; credential metadata is not treated as immutable. Third parties cannot independently reconstruct raw token/account checks from these records.

The [original candidate page](auth-password.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Existing Auth basic, photoUrl and displayName approvals, original observations and aggregation approvals remain unchanged; broad feature labels are not promoted.
