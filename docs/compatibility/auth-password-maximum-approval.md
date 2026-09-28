# Auth password maximum: scoped human approval

21 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of all password-policy boundaries or complete Auth compatibility.

The 21 auth-password-maximum revision 1 cases, limited to the recorded artifact, configuration and corpus; end-user token REST routes, no tenant, local strict profile and recorded production minimum 6 / maximum 4096 password policy. Approved as redacted observations of a generated 4096-character password update and signin, last-character and prefix signin rejection, 4097-character update refusal, subsequent fixed-credential use, selected account-field preservation and recorded deletion/process termination. This does not approve administrator-only field authorization.

Subject: `ed7acb486dc950697ef562d645a8091396669812f2d5556001c86121ba87bd6f`. Recomputed from the complete receipt during offline validation; this approval cannot transfer to a changed subject.

Reviewed commit: `1ac61055283018857864efc877d9d7021e255832`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This records the user's explicit approval, not a cryptographic signature or an independent reviewer authentication mechanism.

| Approved observation | Local / production |
|---|---|
| signup | Matched under recorded controls |
| baseline-signin | Matched under recorded controls |
| maximum-password-change | Matched under recorded controls |
| maximum-token-lookup | Matched under recorded controls |
| old-password-rejected | Matched under recorded controls |
| maximum-password-signin | Matched under recorded controls |
| maximum-password-lookup | Matched under recorded controls |
| maximum-token-refresh | Matched under recorded controls |
| maximum-refreshed-lookup | Matched under recorded controls |
| tail-password-rejected | Matched under recorded controls |
| state-after-tail | Matched under recorded controls |
| prefix-password-rejected | Matched under recorded controls |
| state-after-prefix | Matched under recorded controls |
| oversize-password-rejected | Matched under recorded controls |
| state-after-oversize | Matched under recorded controls |
| preserved-maximum-signin | Matched under recorded controls |
| preserved-maximum-lookup | Matched under recorded controls |
| preserved-maximum-refresh | Matched under recorded controls |
| preserved-refreshed-lookup | Matched under recorded controls |
| delete | Matched under recorded controls |
| deleted-account-absent | Matched under recorded controls |

The recorded inputShape binds the generated 4096-character ASCII password, its last-character variant, 4095-character prefix and 4097-character extension. The fixed ID and update-issued refresh credentials remain usable after oversized-update refusal. Public case results, including exact error codes, must agree between targets.

This approval covers representative ASCII inputs, not all strings, Unicode counting, custom policies, expiry, SDK, Rules or recovery under injected failures. Administrator-only field authorization is explicitly excluded. The separately reported authorization defect does not invalidate these observations or become approved by this record.

[Approval record](../../spec/compatibility/evidence/auth-password-maximum/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-maximum/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-password-maximum/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.

The [original candidate page](auth-password-maximum.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for this subject and these 21 observations. All previous observations and approvals remain unchanged; broad feature labels are not promoted.

[Pinned historical integrity checks](../../tools/compat-history/README.md) verify preservation of older evidence at its original source anchor. Their 304 offline tests are not a rerun of those behaviors on the latest runtime. Current-runtime regression tests and this artifact-bound observation remain separate evidence.
