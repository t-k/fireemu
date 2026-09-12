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

Comparison subject (unapproved): `459c3a79c0b715a19b5afa5925fc6fd05e148e5392a7012f694ad404553b4930`. Production subject compared: `f0e67ab18af75f34ebb1f75c5fb19e288aa1cdedb5a3c4fabf2ad149fc436f73`.

Local artifact `0.7.0` built from the tree at `fd73d17910b694f0433d19fe8c40e13378917db8` (repository HEAD `fd73d17910b694f0433d19fe8c40e13378917db8` at run time) with recorder files at `fd73d17910b694f0433d19fe8c40e13378917db8`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-client-password-change/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-client-password-change/receipt.json) · [Gap ledger](gaps.md).
