# Auth weak-password rejection observations

Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.

Weak-password rejection and preserved credentials through end-user REST under recorded schema 1 ENFORCE length 6–4096 policy; one five-character ASCII update input, original strong credentials and final distinct strong update. No tenant; owned strict local artifact and recorded production settings. Auth-password-rejection revision 1, 16 cases; redacted observations only. No general policy-boundary, elapsed expiry, revocation timing, SDK, Rules, MFA or public npm compatibility claim.

| Case | Local | Production | Expiry seconds (local / production) | Error code (local / production) |
|---|---|---|---|---|
| signup | Matched | Matched | 3600 / 3600 | — / — |
| baseline-signin | Matched | Matched | 3600 / 3600 | — / — |
| baseline-refresh | Matched | Matched | 3600 / 3600 | — / — |
| baseline-refreshed-lookup | Matched | Matched | — / — | — / — |
| weak-password-rejected | Matched | Matched | — / — | WEAK_PASSWORD / WEAK_PASSWORD |
| unchanged-state | Matched | Matched | — / — | — / — |
| original-password-signin | Matched | Matched | 3600 / 3600 | — / — |
| original-password-lookup | Matched | Matched | — / — | — / — |
| original-token-refresh | Matched | Matched | 3600 / 3600 | — / — |
| original-refreshed-lookup | Matched | Matched | — / — | — / — |
| valid-password-change | Matched | Matched | 3600 / 3600 | — / — |
| changed-token-lookup | Matched | Matched | — / — | — / — |
| new-password-signin | Matched | Matched | 3600 / 3600 | — / — |
| new-password-lookup | Matched | Matched | — / — | — / — |
| delete | Matched | Matched | — / — | — / — |
| deleted-account-absent | Matched | Matched | — / — | — / — |

Review subject (no approval granted): `d1fee3f26e44d169ac1719c5af76738a7ced8830f0d1d8e97ce1e8c594b265c8`.

Baseline signin proves the original password works. Its original refresh token is used before and after the refused update, without replacement by newly returned refresh bytes. A five-character ASCII password is sent with that baseline ID token to accounts:update. The expected refusal is HTTP400 WEAK_PASSWORD under the explicitly recorded minimum-six policy. The original ID token then retrieves unchanged selected account fields, and the original password signs in again.

A final distinct strong password update must succeed using the fresh original-password signin ID token. Its returned ID token is used for lookup; new-password signin and lookup must also succeed. This working-update control prevents an implementation that rejects every update from matching. Seven token-returning cases independently check expiry format and 3600 seconds. The final update refresh token is presence-checked only. No elapsed expiry or post-success old-token revocation claim follows.

Passwords, tokens, password hashes, UID and email are not published. Only the classified rejection code is retained, not its raw message. Public validation rechecks error/status/check consistency; selected-field comparisons and credential reuse remain recorder testimony. State checks retain JSON presence/type for localId, email, emailVerified, displayName, photoUrl and disabled, excluding credential timestamps/hashes/provider metadata. Source snapshot hashes and acquisition dates remain unchanged; explicit client policy is not inferred from absent admin configuration.

[Source and case mapping](../../spec/compatibility/evidence/auth-password-rejection/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-rejection/receipt.json). This subject binds corpus, source review, probe/publication code, artifact/build/configuration and process exit.

Admin APIs only establish dedicated-account ownership and cleanup. Bootstrap marker/email and independent UID lookup precede persisted UID readback and any credential mutation. Cleanup uses verified UID/email independently of working passwords; recovered UID is persisted before deletion. Both selectors must confirm absence. Normal cleanup does not prove recovery under injected communication loss or forced termination.

No human approval is inferred from matching observations. All earlier observations and approvals remain unchanged. Other weak values, empty/null, Unicode, minimum accepted or maximum length boundaries, custom policy combinations, password reset, SDK, MFA, actual expiry and full Auth compatibility remain separate verification targets.
