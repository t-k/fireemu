# MFA pending credential lifetime: local comparison

Status: candidate comparison record, not approved. The production record is unchanged; this page adds one owned local run and compares the two row by row.

Row-by-row comparison of the recorded production observations of auth-pending-lifetime with one run of the same corpus on an owned local fireemu artifact (strict profile, --only auth, no configuration change, codes read from the emulator inspection route, pendings aged by advancing the virtual clock). Semantic projections exclude elapsed milliseconds and the measured pending and session ages. A comparison record, not a new production run, not an approval, and not a claim beyond these eight cases.

| Case | Basis | Production outcome / error | Local outcome / error | Same semantic projection |
| --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none | accepted / none | True |
| age-2s-start | diagnostic | accepted / none | accepted / none | True |
| age-2s-finalize | diagnostic | accepted / none | accepted / none | True |
| age-120s-start | diagnostic | accepted / none | accepted / none | True |
| age-120s-finalize | diagnostic | accepted / none | accepted / none | True |
| age-300s-start | diagnostic | accepted / none | accepted / none | True |
| age-300s-finalize | diagnostic | accepted / none | accepted / none | True |
| final-fresh-finalize | control | accepted / none | accepted / none | True |

Differing rows: none.

Production lifetime: usable [2, 120, 300], refused none, lower bound 300 s. Local (owned artifact, virtual clock): usable [2, 120, 300], refused none, lower bound 300 s. The measured pending ages themselves are excluded from the semantic comparison; the compared projection is each row's outcome, error and non-age checks.

Comparison subject (unapproved): `7e8c90169c2262ee3eb93f0031182b8b78fa722a28b5641215b777f145f9117b`. Production subject compared: `14883bcf368b89e4bb7f39e3f5cdb9bb26495026d3d77bc988005d76e5124b9d`.

Local artifact `0.7.0` built from the tree at `e5a52414c3c6307a9b6a670bfc3574411bb624b7` (repository HEAD `e5a52414c3c6307a9b6a670bfc3574411bb624b7` at run time) with recorder files at `e5a52414c3c6307a9b6a670bfc3574411bb624b7`; strict profile, pendings aged by the virtual clock. Owned process exit 0 with listeners closed; every account was deleted with absence confirmation.

A row that differs is an open gap in the ledger, not a verdict about which side is right. Agreement on the remaining rows is agreement in scope, not compatibility coverage, and a matching lower bound is not a matching exact lifetime.

[Comparison record](../../spec/compatibility/evidence/auth-pending-lifetime/local-comparison.json) · [Production receipt](../../spec/compatibility/evidence/auth-pending-lifetime/receipt.json) · [Gap ledger](gaps.md).
