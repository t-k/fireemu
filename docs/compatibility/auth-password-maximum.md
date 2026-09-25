# Auth maximum-password boundary observations

Status: candidate, not approved. Redacted semantic observations, not raw responses or independently signed evidence.

Maximum 4096 / oversize 4097 URL-safe ASCII password REST observation under recorded schema 1 ENFORCE min 6/max 4096 policy, no tenant, owned strict artifact and recorded production auth settings. Includes last-character and 4095-prefix signin controls, fixed credentials after oversize update and recorded cleanup. auth-password-maximum revision 1, 21 cases; candidate only, not all strings, Unicode, custom policies, SDK/Rules or expiry/revocation/fault-recovery guarantees.

| Case | Local checks | Production checks | HTTP local / production | Error local / production | Comparison |
|---|---|---|---|---|---|
| signup | Matched | Matched | 200 / 200 | — / — | Same projected result |
| baseline-signin | Matched | Matched | 200 / 200 | — / — | Same projected result |
| maximum-password-change | Matched | Matched | 200 / 200 | — / — | Same projected result |
| maximum-token-lookup | Matched | Matched | 200 / 200 | — / — | Same projected result |
| old-password-rejected | Matched | Matched | 400 / 400 | INVALID_LOGIN_CREDENTIALS / INVALID_LOGIN_CREDENTIALS | Same projected result |
| maximum-password-signin | Matched | Matched | 200 / 200 | — / — | Same projected result |
| maximum-password-lookup | Matched | Matched | 200 / 200 | — / — | Same projected result |
| maximum-token-refresh | Matched | Matched | 200 / 200 | — / — | Same projected result |
| maximum-refreshed-lookup | Matched | Matched | 200 / 200 | — / — | Same projected result |
| tail-password-rejected | Matched | Matched | 400 / 400 | INVALID_LOGIN_CREDENTIALS / INVALID_LOGIN_CREDENTIALS | Same projected result |
| state-after-tail | Matched | Matched | 200 / 200 | — / — | Same projected result |
| prefix-password-rejected | Matched | Matched | 400 / 400 | INVALID_LOGIN_CREDENTIALS / INVALID_LOGIN_CREDENTIALS | Same projected result |
| state-after-prefix | Matched | Matched | 200 / 200 | — / — | Same projected result |
| oversize-password-rejected | Matched | Matched | 400 / 400 | PASSWORD_DOES_NOT_MEET_REQUIREMENTS / PASSWORD_DOES_NOT_MEET_REQUIREMENTS | Same projected result |
| state-after-oversize | Matched | Matched | 200 / 200 | — / — | Same projected result |
| preserved-maximum-signin | Matched | Matched | 200 / 200 | — / — | Same projected result |
| preserved-maximum-lookup | Matched | Matched | 200 / 200 | — / — | Same projected result |
| preserved-maximum-refresh | Matched | Matched | 200 / 200 | — / — | Same projected result |
| preserved-refreshed-lookup | Matched | Matched | 200 / 200 | — / — | Same projected result |
| delete | Matched | Matched | 200 / 200 | — / — | Same projected result |
| deleted-account-absent | Matched | Matched | 200 / 200 | — / — | Same projected result |

Review subject (no approval granted): `ed7acb486dc950697ef562d645a8091396669812f2d5556001c86121ba87bd6f`.

The initial 47-character password works before update. A random 4096-character URL-safe ASCII replacement is sent to update and subsequent signin; the old password is rejected. Update-issued ID and refresh tokens are used with lookup. The same update-issued refresh bytes are reused after the 4097-character update attempt; the post-attempt state lookup uses the fixed maximum-password signin ID token.

The tail variant is 4096 characters and differs only in its final character; the 4095-character prefix omits that final character. Both must fail signin as bad credentials, followed by selected-field lookup. The oversize update shares all 4096 prefix characters with the working password and appends one ASCII character. inputShape binds these lengths, ASCII and relationships without password bytes or hashes.

Oversize checks require HTTP 400 and a finite classified policy-related error, not arbitrary authentication or rate-limit failure. The exact allowlisted observedError is retained and compared separately across targets; matching broad check booleans alone do not establish identical error behavior. Unknown messages become UNCLASSIFIED_ERROR, never copied raw. The code is observed, not inferred from the minimum-length WEAK_PASSWORD rule.

Successful complete runs prove only these generated inputs under recorded settings. Credential/state failure may leave a private incomplete diagnostic; it is not promoted into complete evidence. Full token signatures, exact revocation timing, elapsed expiry, Unicode counting, every 4096-character input, all prefix lengths, custom policy combinations, SDK/Rules and fault-injected recovery remain outside scope.

Dedicated random account ownership is established by marker/email and independent UID, persisted and read back before updates. Cleanup is by verified UID/email, independent of working credentials; both selectors must report absence. Owned artifact/config hashes, parent-child identity, exit 0 and closed listeners are checked. No production policy change is performed.

Seven token-returning cases across the flow check same-account credentials and expiry format/3600 separately. Selected state includes localId,email,emailVerified,displayName,photoUrl,disabled with presence/type distinctions; credential metadata is excluded. Raw passwords/tokens/UID/email are never public, and these semantic projections remain recorder testimony.

[Source and case mapping](../../spec/compatibility/evidence/auth-password-maximum/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-password-maximum/receipt.json). Prior snapshots retain their acquisition hashes/dates; prior evidence and approvals are unchanged. This candidate does not inherit any approval.
