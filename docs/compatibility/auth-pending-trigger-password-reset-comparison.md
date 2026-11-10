# Held MFA pending credential across password-reset: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of the password-reset trigger (auth-pending-trigger) with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger.

| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | accepted / none | True |
| trigger | diagnostic | accepted / none | accepted / none | True |
| held-start | diagnostic | accepted / none | accepted / none | True |
| held-finalize | diagnostic | accepted / none | accepted / none | True |
| held-lookup | diagnostic | accepted / none | accepted / none | True |
| held-refresh | diagnostic | accepted / none | accepted / none | True |
| final-fresh-finalize | control | accepted / none | accepted / none | True |

Differing rows: none.

Comparison subject (unapproved): `2e4bf5825048ca75ed1ef9505dc0771321fef66fadc5a0f3b24068edc6b5c9b5`. Production subject compared: `9e855872b7e9bdb6e2cfc7c67ea90a7c429c3ad4367caa0b57e1a2d7e89c4975`.

Local artifact `0.7.0` built from the tree at `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299` (repository HEAD `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299` at run time) with recorder files at `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/receipt.json) · [Gap ledger](gaps.md).
