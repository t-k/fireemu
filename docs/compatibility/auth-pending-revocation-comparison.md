# MFA pending credential across an explicit revocation: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of auth-pending-revocation revision 1 with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these eight cases.

| Case | Basis | Production outcome / error | Local outcome / error | Production checks | Local checks | Same semantic projection |
| --- | --- | --- | --- | --- | --- | --- |
| baseline-a-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| baseline-b-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| revoked-a-held-start | diagnostic | accepted / none | accepted / none | sessionInfoPresent=True | sessionInfoPresent=True | True |
| revoked-a-held-finalize | diagnostic | accepted / none | accepted / none | authTimeAtOrAfterValidSince=True, claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | authTimeAtOrAfterValidSince=True, claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| revoked-a-held-lookup | diagnostic | accepted / none | accepted / none | ownerMatches=True | ownerMatches=True | True |
| revoked-a-held-refresh | diagnostic | accepted / none | accepted / none | bearerType=True, derivedLookup=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | bearerType=True, derivedLookup=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | True |
| revoked-a-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| revoked-b-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |

Differing rows: none.

Comparison subject (unapproved): `1c92f13759c0a4e77df4ce884c83f68cf05bccad788d5f9015123cd143dd0560`. Production subject compared: `c6ce38ac6a05b969cdbbf516e77a1fc386e73cb221301d53f98c2c45029a0eb7`.

Local artifact `0.7.0` built from the tree at `4ae036393e582cf76617bd278f73bc8318cc314a` (repository HEAD `b33474382999c140eb32a4279a9116b0abf988bf` at run time) with recorder files at `c0661db2707ae3d110c33cbc7a5b483717b2dcdb`; strict profile. Owned process exit 0 with listeners closed; both accounts were deleted with absence confirmation. The local held credential's ID token carried auth_time 1789140477 against validSince 1789140477 (local virtual clock, whole seconds).

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these eight rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-revocation/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-revocation/receipt.json) · [Approval](auth-pending-revocation-approval.md) · [Gap ledger](gaps.md).
