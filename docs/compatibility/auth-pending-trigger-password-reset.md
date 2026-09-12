# Held MFA pending credential across password-reset

Status: candidate, not approved. Seven redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local behavior is recorded separately in `tools/auth-pending-triggers/README.md`.

Seven sequential REST observations in production only for the password-reset trigger: a fresh phone MFA completion (control) whose session is reused; a pending credential and SMS session are held; then, as the one transition, an admin PASSWORD_RESET OOB link is issued and resetPassword sets a new password; the held credential is presented to mfaSignIn:start and :finalize on the session opened before the transition, with lookup and refresh of any returned tokens; a fresh completion (control) closes the run. Phone MFA with one test phone number, no tenant, no blocking function, one run. For provider-unlink the federated identity is linked administratively as a precondition before the held credential (a refused link aborts the run). The oracle configuration was changed for the run and restored with a digest comparison. Admin is used for owned account setup, readback and cleanup. No human approval, no local artifact comparison, and no claim about other triggers, tenants, SDK or Rules; the held rows are the observation, not a rule about revocation.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 3514 |
| trigger | diagnostic | accepted / none | accountPresent=True, expiresInReturned=False, idTokenReturned=False, noError=True, refreshTokenReturned=False | 5715 |
| held-start | diagnostic | accepted / none | sessionInfoPresent=True | 5979 |
| held-finalize | diagnostic | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 6556 |
| held-lookup | diagnostic | accepted / none | ownerMatches=True | 6841 |
| held-refresh | diagnostic | accepted / none | bearerType=True, derivedLookup=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 7420 |
| final-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 8585 |

Transition (`trigger`): **accepted / none**. Held credential after the transition: start accepted / none, finalize accepted / none. Provider linked as a precondition: False.

Review subject (unapproved): `119e16ff4c44053e2078c03bdc3bef69985e5040426319170adda718cb74399c`.

The held credential and SMS session were created before the transition and presented afterwards on the same session, so the held rows show the transition's effect on the pre-existing credential. The held rows are diagnostic: accepted and refused are both valid observations, and lookup and refresh run only when the held finalize was accepted. Elapsed milliseconds are cumulative from the recorder's measurement origin, sampled when each row is recorded; they are excluded from semantic equality.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the account was deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. The account was deleted with UID and email absence confirmation. The run started from a committed checkout.

Recorded with the recorder files at commit `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299` while the repository was at `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299`. Re-evaluated at publication with the contract at commit `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299`. The observation itself was not re-run.

This does not show what other triggers do, and does not generalize to tenants, blocking functions, SDK or Rules.

[Receipt](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/source-review.json). All earlier evidence and approvals remain unchanged.
