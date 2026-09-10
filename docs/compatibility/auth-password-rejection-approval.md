# Auth password rejection: scoped human approval

16 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of all password-policy boundaries or complete Auth compatibility.

The 16 auth-password-rejection revision 1 cases, limited to the recorded artifact, configuration and corpus; end-user token REST routes, no tenant, local strict profile and recorded production authentication/password-policy settings. Approved as redacted observations: five-character ASCII update refusal under the minimum-six policy, preserved use of the original ID token, refresh token and password after refusal, selected account-field preservation, final valid change and new-credential use, and recorded account deletion/process termination.

Subject: `d1fee3f26e44d169ac1719c5af76738a7ced8830f0d1d8e97ce1e8c594b265c8`. Recomputed from the complete receipt during offline validation; this approval cannot transfer to a changed subject.

Reviewed commit: `503f0ccbaf4664aa7c539fdd2f96ae9f01960538`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This records the user's explicit approval, not a cryptographic signature or an independent reviewer authentication mechanism.

| Approved observation | Local / production |
|---|---|
| signup | Matched under recorded controls |
| baseline-signin | Matched under recorded controls |
| baseline-refresh | Matched under recorded controls |
| baseline-refreshed-lookup | Matched under recorded controls |
| weak-password-rejected | Matched under recorded controls |
| unchanged-state | Matched under recorded controls |
| original-password-signin | Matched under recorded controls |
| original-password-lookup | Matched under recorded controls |
| original-token-refresh | Matched under recorded controls |
| original-refreshed-lookup | Matched under recorded controls |
| valid-password-change | Matched under recorded controls |
| changed-token-lookup | Matched under recorded controls |
| new-password-signin | Matched under recorded controls |
| new-password-lookup | Matched under recorded controls |
| delete | Matched under recorded controls |
| deleted-account-absent | Matched under recorded controls |

A five-character ASCII password update is refused with HTTP400 WEAK_PASSWORD under the recorded minimum-six policy. The fixed original ID token, original password and the same original refresh token remain usable after refusal; refresh-issued ID tokens retrieve the same selected fields. A final distinct strong update and new-password signin/lookup are successful controls. The final update refresh token is presence-checked only. Recorded dedicated-account deletion, UID/email absence and owned-process exit/listener checks are included.

All password-policy boundaries, including exactly six characters, maximum length, Unicode, null/empty and custom combinations, remain outside this approval. Selected-field and credential-use checks do not establish invariance of all internal state. Long-term validity, revocation timing, actual elapsed expiry, SDK, Rules and fault-injected recovery are separate verification targets. Redacted records do not support independent token-signature verification.

[Approval record](../../spec/compatibility/evidence/auth-password-rejection/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-rejection/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-password-rejection/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.

The [original candidate page](auth-password-rejection.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 16 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.

[Pinned historical integrity checks](../../tools/compat-history/README.md) verify preservation of older evidence at its original source anchor. Their 304 offline tests are not a rerun of those behaviors on the latest runtime. Current-runtime regression tests and this artifact-bound observation remain separate evidence.
