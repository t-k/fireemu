# Auth photoUrl updates and deletion: scoped human approval

Twelve scoped cases verified and approved as redacted semantic observations matching the published checks. This is not approval of Auth as a whole.

Photo URL setting, replacement and deletion through REST using end-user tokens; no tenant; local strict profile and recorded production configuration; only the recorded artifact, configuration and auth-photo-url corpus revision 1 twelve cases; approved as redacted semantic observations matching the published checks.

Subject: `23913299c5d414abbdffe0692711f77ead500b639318a09a60a5802bd1f199d2`. Recomputed from the complete receipt during offline validation; approval cannot transfer to a changed subject.

Reviewed commit: `bb2f1a2f15f8aa447bce9395e7322840ec11b5f3`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This repository records the user's explicit approval; it is not a cryptographic signature or independent reviewer authentication mechanism.

| Approved case | Local | Production |
|---|---|---|
| signup | Matched | Matched |
| initial-lookup | Matched | Matched |
| set-photo | Matched | Matched |
| set-photo-lookup | Matched | Matched |
| replace-photo | Matched | Matched |
| replace-photo-lookup | Matched | Matched |
| invalid-token-update | Matched | Matched |
| unchanged-state | Matched | Matched |
| delete-photo | Matched | Matched |
| deleted-photo-lookup | Matched | Matched |
| delete | Matched | Matched |
| deleted-account-absent | Matched | Matched |

The original signup ID token is used for photoUrl updates, lookups and account deletion. Admin APIs support dedicated-account ownership verification and cleanup; this is not an Admin-only profile update test. Setting and replacing use two distinct fixed URLs, and malformed-token refusal attempts a third URL before a valid-token lookup compares selected state.

Expired-token refusal, independent signature validation, token issuance during profile updates, null/empty-string writes, URL boundary conditions, displayName or credential changes and SDK behavior remain unverified by this slice. This is a URL attribute test, not image upload or retrieval. MFA, Rules, OOB, tenant behavior, public npm artifacts and complete Auth or profile-update compatibility are outside this approval.

[Approval record](../../spec/compatibility/evidence/auth-profile/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-profile/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-profile/source-review.json). Token values, passwords and arbitrary returned URLs are not published. A closed enum distinguishes omission, null, empty strings, fixed corpus URLs and other values. Clearing is documented; exact JSON omission is the recorded observation, not a broader inferred specification. Third parties cannot independently reconstruct raw token/account checks from these redacted records.

The [original candidate page](auth-profile.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Existing Auth basic approvals, original observations and aggregation approvals remain unchanged; broad feature labels are not promoted.
