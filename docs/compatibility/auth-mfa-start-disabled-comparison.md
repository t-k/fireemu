# mfaSignIn:start on a disabled account: local comparison

Status: candidate comparison record, not approved. The production record is unchanged; this page adds one owned local run and compares the two row by row.

Row-by-row comparison of the approved production record of auth-mfa-start-disabled with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. A comparison record, not a new production run, not an approval, and not a claim beyond these six cases.

| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | accepted / none | True |
| disabled-start | diagnostic | accepted / none | refused / USER_DISABLED | False |
| disabled-finalize | diagnostic | refused / USER_DISABLED | skipped / none | False |
| reenabled-start | diagnostic | accepted / none | accepted / none | True |
| reenabled-finalize | diagnostic | accepted / none | accepted / none | True |
| final-fresh-finalize | control | accepted / none | accepted / none | True |

Differing rows: disabled-start, disabled-finalize.

Comparison subject (unapproved): `dc7ff6596c4c85156b77c7ae5e5d28ed26449cd869cc5cc98fab29c7b8d79a33`. Production subject compared: `e0fdb84012734f99533f84e7fab173d26e1f0f0a9112f4703d990f1a968df442`.

Local artifact `0.7.0` built from the tree at `7afc750b67845d14573d2a9de9f58dc0688026d5` (repository HEAD `7afc750b67845d14573d2a9de9f58dc0688026d5` at run time) with recorder files at `7afc750b67845d14573d2a9de9f58dc0688026d5`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

A row that differs is an open gap in the ledger, not a verdict about which side is right. Agreement on the remaining rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-mfa-start-disabled/local-comparison.json) · [Production receipt](../../spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json) · [Gap ledger](gaps.md).
