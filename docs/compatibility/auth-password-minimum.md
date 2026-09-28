# Auth minimum-six password change observations

Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.

Exactly six-character URL-safe ASCII password change via fresh end-user REST token, no tenant, strict owned local artifact and recorded production authentication/password-policy configuration. auth-password-minimum revision 1 only. Explicit schema 1 ENFORCE min 6 / max 4096 policy with no additional character requirements. Twelve redacted cases; not all policy boundaries, Unicode, empty/null, custom combinations, actual expiry, revocation timing, SDK, Rules or public npm compatibility.

| Case | Local | Production | Expiry seconds (local / production) |
|---|---|---|---|
| signup | Matched | Matched | 3600 / 3600 |
| baseline-signin | Matched | Matched | 3600 / 3600 |
| minimum-password-change | Matched | Matched | 3600 / 3600 |
| changed-token-lookup | Matched | Matched | — / — |
| old-password-rejected | Matched | Matched | — / — |
| unchanged-state | Matched | Matched | — / — |
| new-password-signin | Matched | Matched | 3600 / 3600 |
| new-password-lookup | Matched | Matched | — / — |
| changed-token-refresh | Matched | Matched | 3600 / 3600 |
| refreshed-lookup | Matched | Matched | — / — |
| delete | Matched | Matched | — / — |
| deleted-account-absent | Matched | Matched | — / — |

Review subject (no approval granted): `b7ad987bdd466784b379a8281a3137e1d1dc259513df426cc9774a68efad7bb4`.

The original random password is proven by baseline signin before accounts:update changes it to a distinct exactly six-character URL-safe ASCII password with returnSecureToken=true. The update response ID token is used for lookup; its refresh token is used for refresh and a further lookup. The old password is expected to fail with HTTP400 INVALID_LOGIN_CREDENTIALS under the recorded improved-email-privacy setting. The new password must sign in as the same UID and its ID token must retrieve that account.

Public inputShape is checked against original length 47, replacement length 6, ASCII true and distinct true, without retaining values or password digests. This is one generated sample, not all six-character strings. Five token-returning cases independently check positive-integer expiry format and the 3600-second expectation. This does not prove elapsed-expiry rejection, token signatures, old-token revocation timing or recent-login limits. Lookup comparisons cover localId, email, emailVerified, displayName, photoUrl and disabled with JSON presence/type distinctions. Password hashes, passwordUpdatedAt, validSince, lastLoginAt and provider synchronization are not part of the unchanged-state claim.

Passwords, tokens, password hashes, UID and email are never published. Selected-field comparisons and token use are recorder testimony; third parties cannot independently reconstruct the raw responses. Source snapshots retain acquisition hashes and times; the recorded client password policy is explicit, not inferred from omitted admin configuration. Custom policies outside the fixed preflight are unsupported by this recorder, not excluded from future compatibility work.

[Source and case mapping](../../spec/compatibility/evidence/auth-password-minimum/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-minimum/receipt.json). This subject binds corpus, source review, probe/publication code, artifact/build/configuration and process exit.

Admin APIs only establish dedicated-account ownership and cleanup. Bootstrap marker/email and independent UID lookup precede persisted UID readback and any credential mutation. Cleanup uses verified UID/email independently of working passwords; recovered UID is persisted before deletion. Both selectors must confirm absence. Normal cleanup does not prove recovery under injected communication loss or forced termination.

No human approval is inferred from either target matching. Existing Auth basic, photoUrl, displayName and aggregation approvals are unchanged and do not cover this new subject. Password reset, SDK, MFA, tenants, other policy boundaries and full Auth compatibility remain separate verification targets.
