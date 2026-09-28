# MFA pending credential lifetime: revision 2 local comparison

Status: candidate comparison record, not approved. The production record is unchanged; this page adds one owned local run and compares the two row by row.

Row-by-row comparison of the recorded production observations of auth-pending-lifetime-boundary with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route, pendings aged by advancing the virtual clock). Semantic projections exclude elapsed milliseconds and the measured pending and session ages. A comparison record, not a new production run, not an approval, and not a claim beyond these ten cases.

| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | accepted / none | True |
| age-600s-start | diagnostic | refused / INVALID_MFA_PENDING_CREDENTIAL | accepted / none | False |
| age-600s-finalize | diagnostic | skipped | accepted / none | False |
| age-1800s-start | diagnostic | refused / INVALID_MFA_PENDING_CREDENTIAL | accepted / none | False |
| age-1800s-finalize | diagnostic | skipped | accepted / none | False |
| age-3300s-start | diagnostic | refused / INVALID_MFA_PENDING_CREDENTIAL | accepted / none | False |
| age-3300s-finalize | diagnostic | skipped | accepted / none | False |
| age-3900s-start | diagnostic | refused / INVALID_MFA_PENDING_CREDENTIAL | refused / INVALID_MFA_PENDING_CREDENTIAL | True |
| age-3900s-finalize | diagnostic | skipped | skipped | True |
| final-fresh-finalize | control | accepted / none | accepted / none | True |

Differing rows: age-600s-start, age-600s-finalize, age-1800s-start, age-1800s-finalize, age-3300s-start, age-3300s-finalize.

Production lifetime: usable none, refused [600, 1800, 3300, 3900], lower bound None s. Local (owned artifact, virtual clock): usable [600, 1800, 3300], refused [3900], lower bound 3300 s. The measured pending ages themselves are excluded from the semantic comparison; the compared projection is each row's outcome, error and non-age checks.

Start acceptance and MFA completion remain distinct; neither a matching survival lower bound nor a matching refusal proves the same TTL. Refusal candidates use each run's measured intervals and do not establish age causality.

Comparison subject (unapproved): `7a81e3c255dc531925f6ce2a656f68f40532a088c8fc745123e3821f9691dbb0`. Production subject compared: `fa7a8be261077f7f670965297772d43afae793dc131d010b1ce32efb87e28f0b`.

Local artifact `0.7.0` built from the tree at `267b10f5a1edf70a2da1a7dff7260e9945f2bd05` (repository HEAD `267b10f5a1edf70a2da1a7dff7260e9945f2bd05` at run time) with recorder files at `267b10f5a1edf70a2da1a7dff7260e9945f2bd05`; strict profile, pendings aged by the virtual clock. Owned process exit 0 with listeners closed; every account was deleted with absence confirmation.

A row that differs is an open gap in the ledger, not a verdict about which side is right. Agreement on the remaining rows is agreement in scope, not compatibility coverage, and a matching lower bound is not a matching exact lifetime.

[Comparison record](../../spec/compatibility/evidence/auth-pending-lifetime-boundary/local-comparison.json) · [Production receipt](../../spec/compatibility/evidence/auth-pending-lifetime-boundary/receipt.json) · [Gap ledger](gaps.md).
