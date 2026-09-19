# Supplementary-character password boundary: scoped human approval

3 input patterns verified and approved: 4095/4096 accepted and 4097 refused under the recorded controls. This is not a claim of complete Unicode/Auth compatibility.

Three auth-password-unicode-boundary revision 1 input patterns, limited to the recorded artifact, configuration and generated patterns. End-user token REST routes, no tenant, local strict profile and recorded production minimum 6 / maximum 4096 password policy. Approval covers 4095/4096 UTF-16-unit acceptance, 4097-unit refusal and error, branch-specific credential use, selected account-state checks and recorded account deletion/process termination. It does not cover all Unicode strings, normalization, minimum-length counting, other API routes, SDK, Rules, elapsed expiry or fault recovery.

Subject: `3b300cebcbddac2db8528f4c9f9ca29b1b767932ce47aede41ee4e6e6946121c`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `e464affdd06065007cedc1b71a031d9453ff31df`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-11.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Approved input pattern | Local / production |
| --- | --- |
| astral-4095 | Identical public results under recorded controls |
| astral-4096 | Identical public results under recorded controls |
| astral-4097 | Identical public results under recorded controls |

The three patterns use separately generated private prefixes, not identical secret passwords across runs. Normalization, truncation of alternative inputs and all Unicode combinations remain separate verification targets. The positive controls use separate accounts; a successful update after refusal on the same account is not claimed. Token values are not public, so independent signature verification is not established by these redacted checks.

[Approval record](../../spec/compatibility/evidence/auth-password-unicode-boundary/approval.json) · [Observation receipt](../../spec/compatibility/evidence/auth-password-unicode-boundary/receipt.json) · [Original mismatch](auth-password-unicode.md).

The [original candidate page](auth-password-unicode-boundary.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these three patterns. The original mismatch, earlier production observations, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.
