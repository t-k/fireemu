# mfaSignIn:start on a disabled account

Status: candidate, not approved. Six redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local behavior is recorded separately in `tools/auth-mfa-start-disabled/README.md`.

Six sequential REST observations in production only: a fresh phone MFA completion (control) while enabled; the account is disabled through privileged accounts:update and read back; the pending credential obtained before the disable is presented to mfaSignIn:start, and its session finalized if one was returned; the account is re-enabled and read back and the same pending credential is started and finalized; a fresh completion (control) closes the run. Phone MFA with one test phone number, no tenant, no blocking function, one run; the pending credential is obtained before the disable. The oracle configuration was changed for the run and restored with a digest comparison. No human approval, no local artifact comparison, no claim about tenants, SDK, Rules or the credential's expiry; the held rows are the observation, not a rule.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 3505 |
| disabled-start | diagnostic | accepted / none | sessionInfoPresent=True | 4826 |
| disabled-finalize | diagnostic | refused / USER_DISABLED | none | 5137 |
| reenabled-start | diagnostic | accepted / none | sessionInfoPresent=True | 6166 |
| reenabled-finalize | diagnostic | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 6757 |
| final-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 7961 |

mfaSignIn:start on the disabled account: **accepted / none**; its finalize: refused / USER_DISABLED. After re-enablement the same pending credential: start accepted / none, finalize accepted / none.

Review subject (unapproved): `e0fdb84012734f99533f84e7fab173d26e1f0f0a9112f4703d990f1a968df442`.

The pending credential was obtained while the account was enabled, then the account was disabled through privileged accounts:update and read back. The held rows are diagnostic: accepted and refused are both valid observations, and each finalize runs only when its own start returned a session. Elapsed milliseconds are cumulative from the recorder's measurement origin, sampled when each row is recorded; they are excluded from semantic equality.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the account was deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. The account was deleted with UID and email absence confirmation. The run started from a committed checkout.

Recorded with the recorder files at commit `21414ddbc71164cd76e0ebd68c020c8ca01cecc0` while the repository was at `21414ddbc71164cd76e0ebd68c020c8ca01cecc0`. Re-evaluated at publication with the contract at commit `74c61c99bc3cfebe9312d7811280bf2a97739d4b`. The observation itself was not re-run.

This does not generalize to tenants, blocking functions, SDK, Rules or the credential's own expiry.

[Receipt](../../spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-mfa-start-disabled/source-review.json). All earlier evidence and approvals remain unchanged.
