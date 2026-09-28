# Blocking function that disables the account: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of auth-blocking-disable revision 1 with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth,functions, the local fixture in tools/auth-blocking-disable/function-local served by the repository's Functions runner, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these twelve cases. Production used the recorded first-generation blocking function; the owned local run used the equivalent second-generation Identity fixture supported by fireemu's Functions runner, installed with npm ci from the committed lockfile. This comparison covers the resulting Auth behavior, not first- versus second-generation Functions SDK parity.

| Case | Basis | Production outcome / error | Local outcome / error | Production checks | Local checks | Same semantic projection |
| --- | --- | --- | --- | --- | --- | --- |
| baseline-b-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |
| hook-c-first-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| hook-c-token-lookup | diagnostic | skipped / none | skipped / none | none | none | True |
| hook-c-token-refresh | diagnostic | skipped / none | skipped / none | none | none | True |
| hook-c-disabled-readback | control | accepted / none | accepted / none | disabledPersisted=False | disabledPersisted=False | True |
| hook-c-second-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| hook-a-first-finalize | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| hook-a-token-lookup | diagnostic | skipped / none | skipped / none | none | none | True |
| hook-a-token-refresh | diagnostic | skipped / none | skipped / none | none | none | True |
| hook-a-disabled-readback | control | accepted / none | accepted / none | disabledPersisted=True | disabledPersisted=True | True |
| hook-a-second-signin | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | none | none | True |
| final-b-fresh-finalize | control | accepted / none | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | True |

Differing rows: none.

Comparison subject (unapproved): `6c130b97db655709ced0357d700314f9be1bce8a7099dfeb18ceeed51b86ae08`. Production subject compared: `81e74c75576f91b3cf889cae905e4eb21437a8f6a86846082b160dc1e4e6db0d`.

Local artifact `0.7.0` built from the tree at `3cadafe7a42effb58b392897298e583a32e51792` (repository HEAD `3cadafe7a42effb58b392897298e583a32e51792` at run time) with recorder files at `3cadafe7a42effb58b392897298e583a32e51792`; strict profile; the Functions runtime served the local fixture through the repository runner at digest `a4a19393c150bf1f…`. Owned process exit 0 with listeners closed; both accounts and the pending state were deleted with absence confirmation.

The local run has no deployment, trigger registration or configuration change, and reads phone codes from the emulator inspection route, so the `hook`, `functionRemoved` and configuration fields of the local report describe the fixture, not a cloud function. A row that differs is an open gap in the ledger, not a verdict about which side is right; the ledger names the follow-up.

[Comparison record](../../spec/compatibility/evidence/auth-blocking-disable/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-blocking-disable/receipt.json) · [Approval](auth-blocking-disable-approval.md) · [Gap ledger](gaps.md).
