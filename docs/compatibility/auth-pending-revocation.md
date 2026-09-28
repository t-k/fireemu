# MFA pending credential across an explicit revocation

Status: candidate, not approved. Eight redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus; the local behavior is pinned separately by the `pending_retry` regressions.

Eight sequential REST observations in production only: fresh phone MFA completions for target A and control B, then the pending credential of A issued before an explicit validSince update is presented to mfaSignIn:start and :finalize after the update and its readback, with lookup and refresh of any returned tokens, followed by fresh completions for A and B. Phone MFA with test phone numbers, no tenant, no blocking function, one run. The oracle configuration was changed for the run and restored with a digest comparison. Admin is used for owned account setup, the validSince update, readback and cleanup. No human approval, no local artifact comparison, no interval measurement between the update and the retry, and no revocation-propagation claim.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-a-fresh-finalize | control | accepted / none | claimEmailMatches, claimSubMatches, derivedLookup, idTokenPresent, noError, refreshTokenPresent, secondFactorClaim | 5654 |
| baseline-b-fresh-finalize | control | accepted / none | claimEmailMatches, claimSubMatches, derivedLookup, idTokenPresent, noError, refreshTokenPresent, secondFactorClaim | 6888 |
| revoked-a-held-start | diagnostic | accepted / none | sessionInfoPresent | 10837 |
| revoked-a-held-finalize | diagnostic | accepted / none | authTimeAtOrAfterValidSince, claimEmailMatches, claimSubMatches, derivedLookup, idTokenPresent, noError, refreshTokenPresent, secondFactorClaim | 11384 |
| revoked-a-held-lookup | diagnostic | accepted / none | ownerMatches | 11679 |
| revoked-a-held-refresh | diagnostic | accepted / none | bearerType, derivedLookup, expiryIsPositiveInteger, expiryMatchesOneHour, idTokenPresent, noError, refreshTokenPresent, uidMatches | 12221 |
| revoked-a-fresh-finalize | control | accepted / none | claimEmailMatches, claimSubMatches, derivedLookup, idTokenPresent, noError, refreshTokenPresent, secondFactorClaim | 13401 |
| revoked-b-fresh-finalize | control | accepted / none | claimEmailMatches, claimSubMatches, derivedLookup, idTokenPresent, noError, refreshTokenPresent, secondFactorClaim | 14587 |

Held credential outcome: **accepted** after the `validSince` update and its readback. The ID token returned for the held credential carried `auth_time` 1789100213 and `iat` 1789100213 against the set `validSince` 1789100211 (whole seconds).

Review subject (unapproved): `c6ce38ac6a05b969cdbbf516e77a1fc386e73cb221301d53f98c2c45029a0eb7`.

The held credential was issued, then after a two-second wait `validSince` was set to the current whole second through privileged `accounts:update` and read back for the target while the control stayed unchanged; only then was the held credential presented. The wait precedes the update, not the retry: the interval between the update and the retry was not measured in this run. Baseline rows completed a different fresh pending credential of each account before the update; fresh rows completed new pending credentials after the held observation. Elapsed milliseconds are cumulative time from the recorder's measurement origin (set before account setup), sampled when each row is recorded after its checks; they are neither request latency nor time since the revocation, and are excluded from semantic equality.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, two test phone numbers with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored in the recorder's final step; the readback matched and the whole-configuration digest equaled the pre-run digest. Both accounts were deleted with UID and email absence confirmation.

Recorded with the recorder files at commit `ad6faeffb062c967d5180b21ced095e12d894932` while the repository was at `c320a29ca9c57d23a705356c106a50ff015adf36`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `8ac4442058194d1cf96700f09a2cee4a0cfc5dfd`, whose completion check is stricter than the recorder's own (a matching configuration digest and a consistent held-credential chain are required). The observation itself was not re-run.

This matches the local implementation, in which finalization does not compare a pending credential's start time with `validSince`; no revocation check was added on the strength of speculation. It does not show that revocation propagates within any interval, that a pre-update refresh token was refused, that password changes behave alike, or anything about tenants, blocking functions, SDK checkRevoked, Rules or the credential's own expiry.

[Receipt](../../spec/compatibility/evidence/auth-pending-revocation/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-revocation/source-review.json). All earlier evidence and approvals remain unchanged.
