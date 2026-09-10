# Auth displayName updates and deletion: scoped human approval

Twelve scoped cases verified and approved as redacted semantic observations matching the published checks. This is not approval of Auth as a whole.

Display name setting, replacement and deletion through REST using end-user tokens; no tenant; local strict profile and recorded production configuration; only the recorded artifact, configuration and auth-display-name corpus revision 1 twelve cases; approved as redacted semantic observations matching the published checks.

Subject: `f6e31fd28a7c05651df454843fe5c40c48b4e70552617b796f1398c702b0d2ec`. Recomputed from the complete receipt during offline validation; approval cannot transfer to a changed subject.

Reviewed commit: `f54ce460f2b743354400cddd56554a3164f30b7b`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This repository records the user's explicit approval; it is not a cryptographic signature or independent reviewer authentication mechanism.

| Approved case | Local | Production |
|---|---|---|
| signup | Matched | Matched |
| initial-lookup | Matched | Matched |
| set-name | Matched | Matched |
| set-name-lookup | Matched | Matched |
| replace-name | Matched | Matched |
| replace-name-lookup | Matched | Matched |
| invalid-token-update | Matched | Matched |
| unchanged-state | Matched | Matched |
| delete-name | Matched | Matched |
| deleted-name-lookup | Matched | Matched |
| delete | Matched | Matched |
| deleted-account-absent | Matched | Matched |

The original signup ID token is used for displayName updates, lookups and account deletion. Initial email/marker and independent UID lookups establish ownership; the private UID record is saved and reread before name mutation. Afterward, UID and email identify the account rather than its mutable name. Admin APIs support ownership and cleanup, not an Admin-only profile update test. Two fixed names test setting and replacement; malformed-token refusal attempts a third name before valid-token lookup compares selected state.

Expired-token refusal, independent signature validation, token issuance during updates, Unicode/length boundaries, null/empty-string writes, simultaneous setting and clearing, credential changes and SDK behavior remain unverified by this slice. Recovery from communication loss or forced termination is not verified; completed cleanup observations do not establish fault-recovery guarantees. MFA, Rules, OOB, tenant behavior, public npm artifacts and complete Auth or profile-update compatibility are outside this approval.

[Approval record](../../spec/compatibility/evidence/auth-display-name/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-display-name/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-display-name/source-review.json). Token values, passwords, account identities and arbitrary returned names are not published. A closed enum distinguishes the initial marker, fixed corpus names, omission, null, empty strings and other values. Clearing is documented; exact JSON omission is the recorded observation, not a broader inferred specification. Third parties cannot independently reconstruct raw token/account checks from these redacted records.

The [original candidate page](auth-display-name.md) and its source-review status are immutable acquisition-time history. This separate approval supersedes their pending-approval status only for the subject and twelve cases above. Existing Auth basic and photoUrl approvals, original observations and aggregation approvals remain unchanged; broad feature labels are not promoted.
