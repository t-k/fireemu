# Blocking function on the creating request (revision 2)

Status: candidate, not approved. Ten redacted production observations, not raw token responses or independent signature verification. No local artifact comparison is part of this record.

Ten sequential REST observations in production only with a first-generation beforeSignIn function deployed for the run that answers disabled: true when the signing-in email's local part starts with a dedicated prefix. Target T signs up with that prefix, so the request that creates the account is the request the function disables; control C signs up with a random local part. Whether T's sign-up is accepted or refused, whether tokens are returned and serve lookup and refresh, whether a record for T exists afterwards and is disabled, what T's own sign-in and a second sign-up do, and C's sign-up, sign-in and photo URL readback are recorded. The function was removed and the trigger registration restored with a digest comparison; accounts were deleted with absence confirmation (or, for a refused creation with no record, the email re-read as absent). No MFA, phone or SMS configuration was touched. No human approval and no local artifact comparison in this record.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| control-c-signup | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 2186 |
| control-c-signup-readback | control | accepted / none | notDisabled=True, photoUrlPersisted=False, recordExists=True | 2535 |
| control-c-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 3142 |
| target-t-signup | diagnostic | refused / USER_DISABLED | none | 4484 |
| target-t-token-lookup | diagnostic | skipped / none | none | 4484 |
| target-t-token-refresh | diagnostic | skipped / none | none | 4484 |
| target-t-record-readback | control | accepted / none | disabledPersisted=True, recordExists=True | 4794 |
| target-t-signin | diagnostic | refused / USER_DISABLED | none | 5083 |
| target-t-second-signup | diagnostic | refused / EMAIL_EXISTS | none | 5471 |
| control-c-final-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 6098 |

Control sign-up photo URL persisted: **False**. Target sign-up: refused; record exists afterwards: True, disabled: True.

Review subject (unapproved): `206490130d5191df9a25a80634315a2b2c0ba190860cc91f7455931a9c25b362`.

The target rows are approved-as-recorded candidates for what a beforeSignIn disable does to the account the same request creates. Refused rows carry the HTTP status and classified error only; the record readback and the second sign-up are the state evidence. The control readback keeps observing that sign-up does not persist a photo URL (revision 1).

Recorded with the recorder and function files at commit `4806cb3670c28fdcbed920516cb8781165393618` while the repository was at `f828b4b5d3737857aa4559b4e41d434f7fd2dca4`. Re-evaluated at publication with the contract at commit `483e157937a267e6be07ae800badb390406d7d56`. Elapsed milliseconds are cumulative from the recorder's measurement origin and excluded from semantic equality.

[Receipt](../../spec/compatibility/evidence/auth-blocking-create-disable/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-blocking-create-disable/source-review.json). All earlier evidence and approvals remain unchanged.
