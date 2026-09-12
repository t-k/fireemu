# Held MFA pending credential across password-reset

Status: candidate, not approved. Seven redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local behavior is recorded separately in `tools/auth-pending-triggers/README.md`.

Seven sequential REST observations in production only for the password-reset trigger: a fresh phone MFA completion (control) whose session is reused; a pending credential and SMS session are held; then, as the one transition, an admin PASSWORD_RESET OOB link is issued and resetPassword sets a new password; the held credential is presented to mfaSignIn:start and :finalize on the session opened before the transition, with lookup and refresh of any returned tokens; a fresh completion (control) closes the run. Phone MFA with one test phone number, no tenant, no blocking function, one run. For provider-unlink the federated identity is linked administratively as a precondition before the held credential (a refused link aborts the run). The oracle configuration was changed for the run and restored with a digest comparison. Admin is used for owned account setup, readback and cleanup. No human approval, no local artifact comparison, and no claim about other triggers, tenants, SDK or Rules; the held rows are the observation, not a rule about revocation.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 3542 |
| trigger | diagnostic | accepted / none | accountPresent=True, noError=True, tokensReturned=False | 6562 |
| held-start | diagnostic | accepted / none | sessionInfoPresent=True | 6855 |
| held-finalize | diagnostic | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 7439 |
| held-lookup | diagnostic | accepted / none | ownerMatches=True | 7762 |
| held-refresh | diagnostic | accepted / none | bearerType=True, derivedLookup=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 8415 |
| final-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 9617 |

Transition (`trigger`): **accepted / none**. Held credential after the transition: start accepted / none, finalize accepted / none. Provider linked as a precondition: False.

Review subject (unapproved): `ac59836dd6f118bf82a4654cdea441a37dfc17d257cf8fd3267a0f653291907f`.

The held credential and SMS session were created before the transition and presented afterwards on the same session, so the held rows show the transition's effect on the pre-existing credential. The held rows are diagnostic: accepted and refused are both valid observations, and lookup and refresh run only when the held finalize was accepted. Elapsed milliseconds are cumulative from the recorder's measurement origin, sampled when each row is recorded; they are excluded from semantic equality.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the account was deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. The account was deleted with UID and email absence confirmation. The run started from a committed checkout.

Recorded with the recorder files at commit `35929c23acdf395cf679672da9cbf16199d8c8b4` while the repository was at `35929c23acdf395cf679672da9cbf16199d8c8b4`. Re-evaluated at publication with the contract at commit `35929c23acdf395cf679672da9cbf16199d8c8b4`. The observation itself was not re-run.

This does not show what other triggers do, and does not generalize to tenants, blocking functions, SDK or Rules.

[Receipt](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/source-review.json). All earlier evidence and approvals remain unchanged.
