# Auth session continuity: scoped human approval

34 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of permanent validity or complete Auth compatibility.

The 34 auth-session-continuity revision 1 observations, limited to the recorded artifact, configuration and corpus; no-password-change end-user REST continuity, no tenant, local strict profile and recorded production authentication/password-policy settings. Approved as redacted observations of successful use of fixed A/B tokens and reference-refresh credentials at target offsets 0/10/30 seconds, successful lookup with refresh-issued ID tokens, fixed invalid-input rejection and recorded deletion/process termination checks.

Subject: `8d8214f936b5061bf584e164f55a4a41c8a0a346354b0cb955c04973e29ee0b2`. Recomputed from the complete receipt during offline validation; this approval cannot transfer to a changed subject.

Reviewed commit: `8c0513c5d7eb1a601f759ea0d3b8d5d243beb05b`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This records the user's explicit approval, not a cryptographic signature or an independent reviewer authentication mechanism.

| Approved observation | Local / production |
|---|---|
| signup | Matched under recorded controls |
| signin-a | Matched under recorded controls |
| signin-b | Matched under recorded controls |
| a-id-baseline | Matched under recorded controls |
| a-refresh-baseline-1 | Matched under recorded controls |
| a-refresh-baseline-2 | Matched under recorded controls |
| b-id-baseline | Matched under recorded controls |
| b-refresh-baseline-1 | Matched under recorded controls |
| b-refresh-baseline-2 | Matched under recorded controls |
| reference-refresh | Matched under recorded controls |
| a-id@0 | Matched under recorded controls |
| a-refresh@0 | Matched under recorded controls |
| b-id@0 | Matched under recorded controls |
| b-refresh@0 | Matched under recorded controls |
| reference-id@0 | Matched under recorded controls |
| reference-refresh@0 | Matched under recorded controls |
| a-id@10000 | Matched under recorded controls |
| a-refresh@10000 | Matched under recorded controls |
| b-id@10000 | Matched under recorded controls |
| b-refresh@10000 | Matched under recorded controls |
| reference-id@10000 | Matched under recorded controls |
| reference-refresh@10000 | Matched under recorded controls |
| a-id@30000 | Matched under recorded controls |
| a-refresh@30000 | Matched under recorded controls |
| b-id@30000 | Matched under recorded controls |
| b-refresh@30000 | Matched under recorded controls |
| reference-id@30000 | Matched under recorded controls |
| reference-refresh@30000 | Matched under recorded controls |
| final-signin | Matched under recorded controls |
| final-lookup | Matched under recorded controls |
| malformed-refresh | Matched under recorded controls |
| unknown-refresh | Matched under recorded controls |
| delete | Matched under recorded controls |
| deleted-account-absent | Matched under recorded controls |

Fixed A/B credentials and reference-refresh credentials succeeded at the recorded observation times; refresh-issued ID tokens also succeeded in lookup. Original credentials were not replaced between observations. Final signin used the original password. Fixed invalid inputs were rejected with INVALID_REFRESH_TOKEN. Recorded dedicated-account deletion, UID/email absence and owned-process exit/listener checks are included.

The 0-second target begins after the reference refresh and its issued-ID lookup complete. The reference refresh uses A's original refresh token and does not establish a third independent session; returned refresh bytes may be unchanged. The password-change and no-change experiments used separate accounts and runs, not simultaneous randomized causal trials. Permanent validity, actual elapsed expiry, whole token lineage, SDK/checkRevoked, Rules, strict causality or exact revocation propagation timing remain outside this approval. Normal cleanup is not fault-injected recovery; decoded JWT metadata is not independent signature verification.

[Approval record](../../spec/compatibility/evidence/auth-session-continuity/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-continuity/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-session-continuity/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.

The [original candidate page](auth-session-continuity.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 34 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.

[Pinned historical integrity checks](../../tools/compat-history/README.md) verify preservation of older evidence at its original source anchor. Their 304 offline tests are not a rerun of those behaviors on the latest runtime. Current-runtime regression tests and this artifact-bound observation remain separate evidence.
