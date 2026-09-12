# Precedence of overlapping refusals: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of auth-refusal-precedence revision 1 with one run of the same corpus on an owned local fireemu artifact built after the end-user accounts:update route was corrected to authenticate before authorizing administrator-only fields (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these nine cases.

| Case | Basis | Production outcome / error | Local outcome / error | Production checks | Local checks | Same semantic projection |
| --- | --- | --- | --- | --- | --- | --- |
| baseline-a-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| baseline-b-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| invalid-token-admin-field-update | diagnostic | refused / INVALID_ID_TOKEN | refused / INVALID_ID_TOKEN | none | none | True |
| disabled-a-wrong-code-finalize | diagnostic | refused / INVALID_CODE | refused / INVALID_CODE | none | none | True |
| disabled-b-correct-code-finalize | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| reenabled-a-held-finalize | diagnostic | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| reenabled-b-held-finalize | diagnostic | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| final-a-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| final-b-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |

Differing rows: none.

Comparison subject (unapproved): `14dd226fd1056ff49fe89393ed90db03d14385b172425af0624dfacbdb038fc2`. Production subject compared: `6c76f862a7b7a2d9ad557ae43d03d3787221089a76e999ae03478e20069fe3c4`.

Local artifact `0.7.0` built from the tree at `ab834f9cbfb5f22437ddda4ce6b18327d6410539` (repository HEAD `c3a7973b31274311ac64835aec761e0bb2a4c1e9` at run time) with recorder files at `ab834f9cbfb5f22437ddda4ce6b18327d6410539`; strict profile. Owned process exit 0 with listeners closed; both accounts were deleted with absence confirmation. The tampered-token update was refused on the corrected artifact with A unchanged on readback (True).

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these nine rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-refusal-precedence/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-refusal-precedence/receipt.json) · [Approval](auth-refusal-precedence-approval.md) · [Gap ledger](gaps.md).
