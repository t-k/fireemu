# mfaSignIn:start on a disabled account: local comparison

Status: candidate comparison record, not approved. The production record is unchanged; this page adds one owned local run and compares the two row by row.

Row-by-row comparison of the approved production record of auth-mfa-start-disabled with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. A comparison record, not a new production run, not an approval, and not a claim beyond these six cases.

| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | accepted / none | True |
| disabled-start | diagnostic | accepted / none | accepted / none | True |
| disabled-finalize | diagnostic | refused / USER_DISABLED | refused / USER_DISABLED | True |
| reenabled-start | diagnostic | accepted / none | accepted / none | True |
| reenabled-finalize | diagnostic | accepted / none | accepted / none | True |
| final-fresh-finalize | control | accepted / none | accepted / none | True |

Differing rows: none.

Comparison subject (unapproved): `04c3b5e15414abb4831f80cb1f1825ce768e0842a01eef7bb724ccf98d153427`. Production subject compared: `c2ac827f2c56fd942e364166919009909070666852bb75f099dd5cf5c0731515`.

Local artifact `0.7.0` built from the tree at `aef95ad3e6f623d6ce8263f52ce20791b67afe68` (repository HEAD `aef95ad3e6f623d6ce8263f52ce20791b67afe68` at run time) with recorder files at `aef95ad3e6f623d6ce8263f52ce20791b67afe68`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

A row that differs is an open gap in the ledger, not a verdict about which side is right. Agreement on the remaining rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-mfa-start-disabled/local-comparison.json) · [Production receipt](../../spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json) · [Gap ledger](gaps.md).
