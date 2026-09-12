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

Comparison subject (unapproved): `31673c1f5a5e3846b4f2e7c270e5f12bc99a536dffa816ad63285251d81ca1b2`. Production subject compared: `ac59836dd6f118bf82a4654cdea441a37dfc17d257cf8fd3267a0f653291907f`.

Local artifact `0.7.0` built from the tree at `35929c23acdf395cf679672da9cbf16199d8c8b4` (repository HEAD `35929c23acdf395cf679672da9cbf16199d8c8b4` at run time) with recorder files at `35929c23acdf395cf679672da9cbf16199d8c8b4`; strict profile. Owned process exit 0 with listeners closed; the account was deleted with absence confirmation.

The local run has no configuration change and reads phone codes from the emulator inspection route, so the configuration fields of the local report are placeholders. A row that differs is an open gap in the ledger, not a verdict about which side is right; agreement on these seven rows is agreement in scope, not compatibility coverage.

[Comparison record](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/local-comparison.json) · [Approved production receipt](../../spec/compatibility/evidence/auth-pending-trigger-password-reset/receipt.json) · [Gap ledger](gaps.md).
