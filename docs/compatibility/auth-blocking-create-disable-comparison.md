# Blocking function on the creating request: local comparison (revision 2)

Status: candidate comparison record, not approved. The production candidate record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the production candidate record of auth-blocking-create-disable revision 2 with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth,functions, the local fixture in tools/auth-blocking-create-disable/function-local served by the repository's Functions runner). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim beyond these ten cases. Production used the recorded first-generation blocking function; the owned local run used the equivalent second-generation Identity fixture supported by fireemu's Functions runner, installed with npm ci from the committed lockfile. This comparison covers the resulting Auth behavior, not first- versus second-generation Functions SDK parity.

| Case | Basis | Production outcome / error | Local outcome / error | Production checks | Local checks | Same semantic projection |
| --- | --- | --- | --- | --- | --- | --- |
| control-c-signup | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| control-c-signup-readback | control | accepted / none | accepted / none | notDisabled=True, photoUrlPersisted=False, recordExists=True | notDisabled=True, photoUrlPersisted=False, recordExists=True | True |
| control-c-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| target-t-signup | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| target-t-token-lookup | diagnostic | skipped / none | skipped / none | none | none | True |
| target-t-token-refresh | diagnostic | skipped / none | skipped / none | none | none | True |
| target-t-record-readback | control | accepted / none | accepted / none | disabledPersisted=True, recordExists=True | disabledPersisted=True, recordExists=True | True |
| target-t-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| target-t-second-signup | diagnostic | refused / EMAIL_EXISTS | refused / EMAIL_EXISTS | none | none | True |
| control-c-final-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |

Differing rows: none.

Comparison subject (unapproved): `98e5a0e723c3dfba46f2ed4dcf9074ca179888c9e47bd2b79de875924c82345b`. Production subject compared: `b6e1ad0224e1464f80d6c2c728550e5099b397d5982c6890895714210f5b97c5`.

Local artifact `0.7.0` built from the tree at `3cadafe7a42effb58b392897298e583a32e51792` (repository HEAD `3cadafe7a42effb58b392897298e583a32e51792` at run time) with recorder files at `3cadafe7a42effb58b392897298e583a32e51792`; strict profile; the Functions runtime served the local fixture through the repository runner at digest `a4a19393c150bf1f…`. Owned process exit 0 with listeners closed; both accounts and the pending state were deleted with absence confirmation.

The local run has no deployment, trigger registration or configuration change, and reads phone codes from the emulator inspection route, so the `hook`, `functionRemoved` and configuration fields of the local report describe the fixture, not a cloud function. A row that differs is an open gap in the ledger, not a verdict about which side is right; the ledger names the follow-up.

[Comparison record](../../spec/compatibility/evidence/auth-blocking-create-disable/local-comparison.json) · [Production candidate receipt](../../spec/compatibility/evidence/auth-blocking-create-disable/receipt.json) · [Candidate page](auth-blocking-create-disable.md) · [Gap ledger](gaps.md).
