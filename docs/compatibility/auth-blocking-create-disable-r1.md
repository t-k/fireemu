# Blocking function on the creating request: revision 1 (selector not persisted)

Status: candidate, not approved. Ten redacted production observations. This revision did not observe a created-then-disabled account: production does not persist the sign-up photo URL the function selected on, which is the finding this record documents.

Ten sequential REST observations in production only with a first-generation beforeSignIn function deployed for the run that answers disabled: true for a sign-up photo URL selector. Revision 1 of the corpus: production did not persist the sign-up photo URL (the control readback shows it absent), so the selector never matched and the target was created, signed in and refreshed like the control; the created-then-disabled case itself was therefore not observed by this revision. The function was removed and the trigger registration restored with a digest comparison; both accounts were deleted with absence confirmation. No MFA, phone or SMS configuration was touched. No human approval and no local artifact comparison.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| control-c-signup | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 1994 |
| control-c-signup-readback | control | accepted / none | notDisabled=True, photoUrlPersisted=False, recordExists=True | 2322 |
| control-c-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 2961 |
| target-t-signup | diagnostic | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 4583 |
| target-t-token-lookup | diagnostic | accepted / none | ownerMatches=True | 4891 |
| target-t-token-refresh | diagnostic | accepted / none | bearerType=True, derivedLookup=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 5446 |
| target-t-record-readback | control | accepted / none | disabledPersisted=False, recordExists=True | 5749 |
| target-t-signin | diagnostic | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 6380 |
| target-t-second-signup | diagnostic | refused / EMAIL_EXISTS | none | 6748 |
| control-c-final-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 7394 |

Control sign-up photo URL persisted: **False**. Target sign-up: accepted; record exists afterwards: True, disabled: False.

Review subject (unapproved): `42916d35d24a90b70dbc95d0f8c5a99172b62b279c267a45fecf332f4dcbaa55`.

What this record supports: a photoUrl sent with accounts:signUp is not on the record read back through privileged lookup and is not visible to a beforeSignIn function on the creating request; fireemu keeps ignoring the field. What it does not support: any statement about a created-then-disabled account, which revision 2 of the corpus (an email-prefix selector) is designed to observe.

Recorded with the recorder and function files at commit `cfcbb29101bb0b6dd0f3ba8d2b90d07ce1fb831f` while the repository was at `cfcbb29101bb0b6dd0f3ba8d2b90d07ce1fb831f`. Re-evaluated at publication with the contract at commit `4806cb3670c28fdcbed920516cb8781165393618`. Elapsed milliseconds are cumulative from the recorder's measurement origin and excluded from semantic equality.

[Receipt](../../spec/compatibility/evidence/auth-blocking-create-disable-r1/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-blocking-create-disable-r1/source-review.json). All earlier evidence and approvals remain unchanged.
