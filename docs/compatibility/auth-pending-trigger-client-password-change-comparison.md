# Held MFA pending credential across client-password-change: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of the client-password-change trigger (auth-pending-trigger) with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger.

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

Comparison subject (unapproved): `346a989081ba9b88c41051218266f884381923686d15a4aa47330cbd12e5098c`. Production subject compared: `c8b4c62bdb78324de719eac312fa1c8abccff78b00932c6056b153b5a0be14e9`.

Local artifact `0.7.0` built from the tree at `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299` (repository HEAD `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299` at run time) with recorder files at `d3c2f4fc3772af8cd9a5095c481e42bc4ee4d299`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-client-password-change/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-client-password-change/receipt.json) · [Gap ledger](gaps.md).
