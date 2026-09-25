# Auth password minimum: scoped human approval

12 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of all password-policy boundaries or complete Auth compatibility.

The 12 auth-password-minimum revision 1 cases, limited to the recorded artifact, configuration and corpus; fresh end-user ID token REST routes, no tenant, local strict profile and recorded production authentication settings and schema 1 ENFORCE password policy with minimum 6, maximum 4096 and no additional character requirements. Approved as redacted observations of a generated six-character URL-safe ASCII password change, old-password rejection, new-password same-account signin, actual use of update-issued ID and refresh tokens, selected account-field preservation and recorded deletion/process termination.

Subject: `b7ad987bdd466784b379a8281a3137e1d1dc259513df426cc9774a68efad7bb4`. Recomputed from the complete receipt during offline validation; this approval cannot transfer to a changed subject.

Reviewed commit: `db39f7133efbe009474308e9ce52df56a989a136`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This records the user's explicit approval, not a cryptographic signature or an independent reviewer authentication mechanism.

| Approved observation | Local / production |
|---|---|
| signup | Matched under recorded controls |
| baseline-signin | Matched under recorded controls |
| minimum-password-change | Matched under recorded controls |
| changed-token-lookup | Matched under recorded controls |
| old-password-rejected | Matched under recorded controls |
| unchanged-state | Matched under recorded controls |
| new-password-signin | Matched under recorded controls |
| new-password-lookup | Matched under recorded controls |
| changed-token-refresh | Matched under recorded controls |
| refreshed-lookup | Matched under recorded controls |
| delete | Matched under recorded controls |
| deleted-account-absent | Matched under recorded controls |

The recorded inputShape confirms original length 47, replacement length 6, URL-safe ASCII and distinct credentials. The baseline password works before the update and is rejected afterward; the generated new password signs in as the same account. Both the update-issued ID token and the same update response's refresh token are used, with lookup after refresh. Selected field checks and recorded dedicated-account deletion, UID/email absence and owned-process exit/listener checks are included.

This approval covers the generated representative input, not every six-character combination. Unicode, other lengths and policy boundaries, empty/null, custom policy combinations, actual expiry, revocation timing, SDK, Rules and fault-injected recovery remain separate verification targets. Selected account fields do not establish invariance of all internal state. Redacted observations are recorder testimony, not independent token-signature verification or a password-security recommendation.

[Approval record](../../spec/compatibility/evidence/auth-password-minimum/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-minimum/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-password-minimum/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.

The [original candidate page](auth-password-minimum.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 12 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.

[Pinned historical integrity checks](../../tools/compat-history/README.md) verify preservation of older evidence at its original source anchor. Their 304 offline tests are not a rerun of those behaviors on the latest runtime. Current-runtime regression tests and this artifact-bound observation remain separate evidence.
