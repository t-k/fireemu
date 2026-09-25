# Auth password change observations

Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.

Password change REST using fresh end-user tokens; no tenant; strict owned local artifact and recorded production configuration; auth-password corpus revision 1 only. Production requires improved email privacy, omitted admin passwordPolicyConfig and explicit client policy schema 1 / ENFORCE / length 6-4096. Redacted semantic observations, not independent JWT verification, revocation timing, expired-token enforcement, recent-login boundaries, password-policy boundaries, SDK, MFA, Rules or public npm compatibility.

| Case | Local | Production | Expiry seconds (local / production) |
|---|---|---|---|
| signup | Matched | Matched | 3600 / 3600 |
| baseline-signin | Matched | Matched | 3600 / 3600 |
| change-password | Matched | Matched | 3600 / 3600 |
| changed-token-lookup | Matched | Matched | — / — |
| old-password-rejected | Matched | Matched | — / — |
| unchanged-state | Matched | Matched | — / — |
| new-password-signin | Matched | Matched | 3600 / 3600 |
| new-password-lookup | Matched | Matched | — / — |
| changed-token-refresh | Matched | Matched | 3600 / 3600 |
| refreshed-lookup | Matched | Matched | — / — |
| delete | Matched | Matched | — / — |
| deleted-account-absent | Matched | Matched | — / — |

Review subject (no approval granted): `aaa9cf7bd198aa7ca6c9215718323539c50ff339d02ab0392f8d26ba85eaa9fb`.

The original random password is proven by baseline signin before accounts:update changes it to a distinct random password with returnSecureToken=true. The update response ID token is used for lookup; its refresh token is used for refresh and a further lookup. The old password is expected to fail with HTTP400 INVALID_LOGIN_CREDENTIALS under the recorded improved-email-privacy setting. The new password must sign in as the same UID and its ID token must retrieve that account.

Five token-returning cases independently check positive-integer expiry format and the 3600-second expectation. This does not prove elapsed-expiry rejection, token signatures, old-token revocation timing or recent-login limits. Lookup comparisons cover localId, email, emailVerified, displayName, photoUrl and disabled with JSON presence/type distinctions. Password hashes, passwordUpdatedAt, validSince, lastLoginAt and provider synchronization are not part of the unchanged-state claim.

Passwords, tokens, password hashes, UID and email are never published. Selected-field comparisons and token use are recorder testimony; third parties cannot independently reconstruct the raw responses. Source snapshots retain acquisition hashes and times; the recorded client password policy is explicit, not inferred from omitted admin configuration. Custom policies outside the fixed preflight are unsupported by this recorder, not excluded from future compatibility work.

[Source and case mapping](../../spec/compatibility/evidence/auth-password/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password/receipt.json). This subject binds corpus, source review, probe/publication code, artifact/build/configuration and process exit.

Admin APIs only establish dedicated-account ownership and cleanup. Bootstrap marker/email and independent UID lookup precede persisted UID readback and any credential mutation. Cleanup uses verified UID/email independently of working passwords; recovered UID is persisted before deletion. Both selectors must confirm absence. Normal cleanup does not prove recovery under injected communication loss or forced termination.

No human approval is inferred from either target matching. Existing Auth basic, photoUrl, displayName and aggregation approvals are unchanged and do not cover this new subject. Password reset, SDK, MFA, tenants, policy boundaries and full Auth compatibility remain separate verification targets.
