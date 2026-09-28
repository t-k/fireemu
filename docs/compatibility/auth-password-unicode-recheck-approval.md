# Unicode password recheck: scoped human approval

8 input patterns verified and approved as a recheck of the corrected local artifact against saved production observations. This is not a new production run or a claim of complete Unicode/Auth compatibility.

Eight recorded input patterns rechecked on the corrected local artifact against unchanged saved production observations. End-user token REST routes, no tenant, local strict profile and the recorded minimum 6 / maximum 4096 password policy. Approval covers acceptance/refusal, branch-specific credential use, selected account-state checks and recorded account deletion/process termination. This is not a new production run; random prefixes and accounts differ between runs. It does not cover all Unicode strings, normalization, length limits on other routes, elapsed expiry, SDK, Rules or fault recovery.

Subject: `5f13dcc611017940756158cbf225cc2efd85ffeed4d40fca4445039d7088a885`. Recomputed from the complete recheck receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `6618d9365402f9d05e6f390ca1ef623052dac4ae`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-10.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Approved input pattern | Corrected local / saved production |
| --- | --- |
| ascii-at | Identical public results under recorded controls |
| ascii-over | Identical public results under recorded controls |
| bmp-byte-at | Identical public results under recorded controls |
| bmp-byte-over | Identical public results under recorded controls |
| astral-unit-at | Identical public results under recorded controls |
| astral-unit-over | Identical public results under recorded controls |
| bmp-scalar-at | Identical public results under recorded controls |
| bmp-scalar-over | Identical public results under recorded controls |

The eight patterns use separately generated private prefixes, not identical secret passwords across runs. The exact 4097-unit supplementary-character boundary, normalization, truncation of alternative inputs and all Unicode combinations remain separate verification targets. Token values are not public, so independent signature verification is not established by these redacted checks.

[Approval record](../../spec/compatibility/evidence/auth-password-unicode-recheck/approval.json) · [Recheck receipt](../../spec/compatibility/evidence/auth-password-unicode-recheck/receipt.json) · [Original mismatch](auth-password-unicode.md).

The [recheck candidate page](auth-password-unicode-recheck.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these eight patterns. The original mismatch, original production observation, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.
