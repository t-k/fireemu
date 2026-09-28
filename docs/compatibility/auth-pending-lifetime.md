# MFA pending credential lifetime

Status: candidate, not approved. Eight redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local behavior is recorded separately in `tools/auth-pending-lifetime/README.md`.

Eight sequential REST observations in production only: a fresh phone MFA completion (control); then, for each of three pending credentials held untouched from a common origin and aged by real waiting to about 2, 120 and 300 seconds, mfaSignIn:start with a freshly opened SMS session (so only the pending age is large) and, on an acceptance, a finalize of that fresh session; a fresh completion (control) closes the run. One independent account per age, phone MFA with one test phone number, no tenant, no blocking function, one run. The oracle configuration was changed for the run and restored with a digest comparison. This establishes a lower bound on the pending lifetime; a refused age records its error but does not, in this revision, establish an upper bound, because the corpus does not prove a refusal is due to expiry; it pins no exact TTL and no error precedence. No human approval, no local artifact comparison, no claim about tenants, SDK or Rules, and no separation of pending-versus-session expiry.

| Case | Basis | Pending age (s) | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | 0 | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 11270 |
| age-2s-start | diagnostic | 2 | accepted / none | sessionInfoPresent=True | 13872 |
| age-2s-finalize | diagnostic | 2 | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 14473 |
| age-120s-start | diagnostic | 120 | accepted / none | sessionInfoPresent=True | 132254 |
| age-120s-finalize | diagnostic | 120 | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 132893 |
| age-300s-start | diagnostic | 300 | accepted / none | sessionInfoPresent=True | 312591 |
| age-300s-finalize | diagnostic | 300 | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 313546 |
| final-fresh-finalize | control | 0 | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 314774 |

Sampled ages: 2, 120, 300 s. Verified usable: [2, 120, 300]. Refused: none. Indeterminate (accepted without a verified token): none. This establishes a lower bound of **300 s** on the pending lifetime (not an infinite lifetime). A refused age records its error, but this revision does not prove a refusal is due to expiry, so it asserts no lifetime upper bound.

Review subject (unapproved): `5f2c4fa33a377302901d659cd5e9d9fd588fb893d140dc10eb6baf7a2d489698`.

Each pending credential was obtained near a common origin and left untouched until its own diagnostic, so no intermediate access could extend it; the SMS session was opened fresh at the diagnostic, so its age at finalize is recorded as an interval near zero while only the pending age grows. A sampled age is counted usable only when its start returned a session and its finalize both succeeded and passed every identity check; an accepted finalize with a missing or unverifiable token is recorded but counts as indeterminate, not usable. A refused start records its error and skips its finalize. The pending age at start and the session age at finalize are kept in a separate timing region on each row, saved on refusal too, and excluded from semantic equality along with the elapsed milliseconds, since they vary across runs and clocks.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the accounts were deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. Every account was deleted with UID and email absence confirmation. The run aged by real waiting and started from a committed checkout.

Recorded with the recorder files at commit `e5a52414c3c6307a9b6a670bfc3574411bb624b7` while the repository was at `e5a52414c3c6307a9b6a670bfc3574411bb624b7`. Re-evaluated at publication with the contract at commit `e5a52414c3c6307a9b6a670bfc3574411bb624b7`. The observation itself was not re-run.

This does not pin the exact pending lifetime or error precedence, does not separate pending-versus-session expiry, and does not generalize to tenants, blocking functions, SDK or Rules.

[Receipt](../../spec/compatibility/evidence/auth-pending-lifetime/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-lifetime/source-review.json). All earlier evidence and approvals remain unchanged.
