# Held MFA pending credential across admin-password-update: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of the admin-password-update trigger (auth-pending-trigger) with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger.

| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | accepted / none | True |
| trigger | diagnostic | accepted / none | accepted / none | False |
| held-start | diagnostic | accepted / none | accepted / none | True |
| held-finalize | diagnostic | accepted / none | accepted / none | True |
| held-lookup | diagnostic | accepted / none | accepted / none | True |
| held-refresh | diagnostic | accepted / none | accepted / none | True |
| final-fresh-finalize | control | accepted / none | accepted / none | True |

Differing rows: trigger.

Comparison subject (unapproved): `3e1c6c477aa4bc87c6de5979d9d9cec4944bba25c58b1f6edc4bd59a4580f41e`. Production subject compared: `96e766de06073fcf0e5218f6f30fbb8b8ccdf727a3704b10dda83f57199cf38a`.

Local artifact `0.7.0` built from the tree at `f805bc7b432af817f8163bf17f738752c9ff80d0` (repository HEAD `f805bc7b432af817f8163bf17f738752c9ff80d0` at run time) with recorder files at `f805bc7b432af817f8163bf17f738752c9ff80d0`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-admin-password-update/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-admin-password-update/receipt.json) · [Gap ledger](gaps.md).
