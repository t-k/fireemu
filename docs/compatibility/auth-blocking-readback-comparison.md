# Hook-applied disable, readback timing: local comparison

Status: candidate comparison record, not approved. The production candidate record is unchanged; this page adds one run of the same corpus on the owned local artifact built after the persistence rule was corrected, and compares the two row by row.

Row-by-row comparison of the production candidate record of auth-blocking-readback revision 1 with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth,functions, the disabling local fixture from tools/auth-blocking-disable served by the repository's Functions runner). Semantic projections exclude elapsed milliseconds and the measured seconds since the refusal. This is a comparison record, not a new production run, not an approval, and not a claim beyond these eleven cases on one time axis.

| Case | Basis | Production outcome / error | Local outcome / error | Production checks | Local checks | Same semantic projection |
| --- | --- | --- | --- | --- | --- | --- |
| control-z-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| x-readback-before | control | accepted / none | accepted / none | disabledPersisted=False, secondsSinceRefusal=None | disabledPersisted=False, secondsSinceRefusal=None | True |
| x-first-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| x-readback-immediate | control | accepted / none | accepted / none | disabledPersisted=False, secondsSinceRefusal=0 | disabledPersisted=False, secondsSinceRefusal=0 | True |
| x-readback-after-5s | control | accepted / none | accepted / none | disabledPersisted=False, secondsSinceRefusal=5 | disabledPersisted=False, secondsSinceRefusal=5 | True |
| x-readback-after-30s | control | accepted / none | accepted / none | disabledPersisted=False, secondsSinceRefusal=31 | disabledPersisted=False, secondsSinceRefusal=30 | True |
| x-second-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| y-first-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| y-readback-after-30s-unread | control | accepted / none | accepted / none | disabledPersisted=False, secondsSinceRefusal=30 | disabledPersisted=False, secondsSinceRefusal=30 | True |
| y-second-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| control-z-final-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |

Differing rows: none.

Comparison subject (unapproved): `59093c4e855832048615ace2b5a941c73a42a81f6f65014ad62f6f0858e58f23`. Production subject compared: `81dae6d26f525a31e121abb87669e875026696f50ce44a223fc9c396c9806b9b`.

Local artifact `0.7.0` built from the tree at `481b76e844a59721ddb1934ab9a3527bb246be74` (repository HEAD `98be37595fcd5b69bdae10dfad06ea0da8e541b8` at run time) with recorder files at `512b043559ecce10a2614c5cf3ea43f816dab347`; strict profile; the Functions runtime served the local fixture through the repository runner at digest `a4a19393c150bf1f…`. Owned process exit 0 with listeners closed; both accounts and the pending state were deleted with absence confirmation.

The local run has no deployment, trigger registration or configuration change, and reads phone codes from the emulator inspection route, so the `hook`, `functionRemoved` and configuration fields of the local report describe the fixture, not a cloud function. A row that differs is an open gap in the ledger, not a verdict about which side is right; the ledger names the follow-up.

[Comparison record](../../spec/compatibility/evidence/auth-blocking-readback/local-comparison.json) · [Production candidate receipt](../../spec/compatibility/evidence/auth-blocking-readback/receipt.json) · [Candidate page](auth-blocking-readback.md) · [Gap ledger](gaps.md).
