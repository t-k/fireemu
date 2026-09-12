# Held MFA pending credential across provider-unlink: local comparison

Status: candidate comparison record, not approved. The approved production record is unchanged; this page adds one run of the same corpus on an owned local artifact and compares the two row by row.

Row-by-row comparison of the approved production record of the provider-unlink trigger (auth-pending-trigger) with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route). Semantic projections exclude elapsed milliseconds. This is a comparison record, not a new production run, not an approval, and not a claim that the local artifact matches on anything outside these seven cases or for any other trigger.

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

Comparison subject (unapproved): `af6b957623866fd7cf9471b1d401064856699cf223f94b2a444a725c3da82628`. Production subject compared: `cd52dfc468f95ed9b36a69df4e868c4b33c7461159da45affadf578903b8ccd0`.

Local artifact `0.7.0` built from the tree at `74bcce6f17ddb366641797afc29042a597a636b1` (repository HEAD `74bcce6f17ddb366641797afc29042a597a636b1` at run time) with recorder files at `74bcce6f17ddb366641797afc29042a597a636b1`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-provider-unlink/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-provider-unlink/receipt.json) · [Gap ledger](gaps.md).
