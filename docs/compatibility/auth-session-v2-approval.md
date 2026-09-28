# Auth session token revision 2: scoped human approval

34 observations verified and approved as redacted REST observations matching the published comparison conditions. This is not a guarantee of universal immediate revocation or complete Auth compatibility.

The 34 auth-session-v2 revision 2 observations, limited to the recorded artifact, configuration and corpus; end-user REST routes, no tenant, local strict profile and recorded production authentication/password-policy settings. Approved as redacted observations matching the published comparison conditions: fixed pre-change A/B ID and refresh tokens, changed-response token controls, finite target offsets 0/10/30 seconds, and two fixed invalid-refresh input controls.

Subject: `2650710c03f4ea3fce3e066ef14be16be801b63af14916666b7d7a5bfb24e4f1`. Recomputed from the complete receipt during offline validation; this approval cannot transfer to a changed subject.

Reviewed commit: `e7360c5be399a4657dc33c1cdb7b49d47857347c`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

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
| change-password | Matched under recorded controls |
| a-id@0 | Matched under recorded controls |
| a-refresh@0 | Matched under recorded controls |
| b-id@0 | Matched under recorded controls |
| b-refresh@0 | Matched under recorded controls |
| changed-id@0 | Matched under recorded controls |
| changed-refresh@0 | Matched under recorded controls |
| a-id@10000 | Matched under recorded controls |
| a-refresh@10000 | Matched under recorded controls |
| b-id@10000 | Matched under recorded controls |
| b-refresh@10000 | Matched under recorded controls |
| changed-id@10000 | Matched under recorded controls |
| changed-refresh@10000 | Matched under recorded controls |
| a-id@30000 | Matched under recorded controls |
| a-refresh@30000 | Matched under recorded controls |
| b-id@30000 | Matched under recorded controls |
| b-refresh@30000 | Matched under recorded controls |
| changed-id@30000 | Matched under recorded controls |
| changed-refresh@30000 | Matched under recorded controls |
| new-password-signin | Matched under recorded controls |
| new-password-lookup | Matched under recorded controls |
| malformed-refresh | Matched under recorded controls |
| unknown-refresh | Matched under recorded controls |
| delete | Matched under recorded controls |
| deleted-account-absent | Matched under recorded controls |

The original A/B credentials were usable before the password change and remained fixed during sampling. Old-ID accounts:lookup and old-refresh exchange are distinct routes. Changed-response credentials and final new-password signin/lookup are positive controls; successful refresh is distinguished from successful use of its issued ID token. The two deliberately invalid inputs retain INVALID_REFRESH_TOKEN rather than the known-revoked TOKEN_EXPIRED category. Approval also includes the recorded dedicated-account deletion/UID-and-email absence and owned-process exit/listener checks.

The 0-second target begins after the password-change response, not at the server's internal mutation instant. Exact propagation latency, uniform immediate revocation across all routes, same-second issuance/change, whole rotated-session lineage, no-change longitudinal controls, Admin SDK verifyIdToken/checkRevoked, Rules, actual elapsed expiry, MFA, public npm artifacts and SDK behavior remain outside this approval. Successful normal cleanup does not prove communication-loss or forced-termination recovery. Decoded JWT timing metadata is not independently verified token-signature evidence.

[Approval record](../../spec/compatibility/evidence/auth-session-v2/approval.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-v2/receipt.json) · [Source and case mapping](../../spec/compatibility/evidence/auth-session-v2/source-review.json). Tokens, passwords and account identifiers are not published; third parties cannot reconstruct raw token checks from these projections.

The [original candidate page](auth-session-v2.md) remains immutable acquisition-time history. This separate approval supersedes its pending status only for the subject and 34 observations above. Revision 1's six differences and all earlier observations/approvals remain unchanged; broad feature labels are not promoted.

[Pinned historical integrity checks](../../tools/compat-history/README.md) verify preservation of older evidence at its original source anchor. Their 304 offline tests are not a rerun of those behaviors on the latest runtime. Current-runtime regression tests and this artifact-bound observation remain separate evidence.
