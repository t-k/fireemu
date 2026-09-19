# Administrative updates to a disabled account: local comparison

Status: candidate comparison record, not approved. The production candidate record is unchanged; this page adds one run of the same corpus on an owned local artifact built after the token rule was corrected, and compares the two row by row.

Row-by-row comparison of the production candidate record of auth-disabled-admin-update revision 1 with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim beyond these ten cases.

| Case | Basis | Production outcome / error | Local outcome / error | Production checks | Local checks | Same semantic projection |
| --- | --- | --- | --- | --- | --- | --- |
| baseline-a-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| baseline-b-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| disabled-a-password-update | diagnostic | accepted / none | accepted / none | localIdMatches=True, noError=True, readbackApplied=True, tokensReturned=False | localIdMatches=True, noError=True, readbackApplied=True, tokensReturned=False | True |
| disabled-a-update-token-lookup | diagnostic | skipped / none | skipped / none | none | none | True |
| disabled-a-update-token-refresh | diagnostic | skipped / none | skipped / none | none | none | True |
| disabled-a-photo-update | diagnostic | accepted / none | accepted / none | localIdMatches=True, noError=True, readbackApplied=True, tokensReturned=False | localIdMatches=True, noError=True, readbackApplied=True, tokensReturned=False | True |
| disabled-a-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| disabled-b-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| reenabled-a-signin | diagnostic | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| reenabled-b-signin | control | accepted / none | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |

Differing rows: none.

Comparison subject (unapproved): `87086b8343892b9bffd0a8e913b72658c6d277e2ea86d26dd88382b9acb8cc90`. Production subject compared: `c5edbe9850fc52c66c666ca0c62961af3c4ad214fc074a950380c592960560fd`.

Local artifact `0.7.0` built from the tree at `481b76e844a59721ddb1934ab9a3527bb246be74` (repository HEAD `2b60137674807217a82e7033d220f57f0260d85b` at run time) with recorder files at `8dddb9736d64e9acc68fc2e73f2483ef98be43ec`; strict profile. Owned process exit 0 with listeners closed; both accounts were deleted with absence confirmation.

The local run has no configuration change; the local configuration fields are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these ten rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-disabled-admin-update/local-comparison.json) · [Production candidate receipt](../../spec/compatibility/evidence/auth-disabled-admin-update/receipt.json) · [Candidate page](auth-disabled-admin-update.md) · [Gap ledger](gaps.md).
