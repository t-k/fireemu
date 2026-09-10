# Account disable / re-enable recheck: scoped human approval

18 observations verified and approved within this limited scope as a recheck of the corrected local artifact against saved production observations. This is not a new production run or a claim of complete Auth compatibility.

Eighteen observations rechecked on the recorded corrected local artifact against unchanged saved production observations. No tenant, local strict profile and recorded production authentication/password-policy settings. Admin disables and re-enables owned target A; independent B is the unaffected control. Each phase follows the recorded order: password signin, fixed original ID-token lookup, then fixed original refresh-token exchange; successful issued tokens are used for lookup. Approval includes selected state checks, Admin account cleanup and UID/email absence, and owned process termination. Only elapsedMs is excluded from semantic comparison: the three disabled-A routes return USER_DISABLED and the remaining fifteen succeed. This is not a new production run. Approval does not cover all operation orders after re-enable, long-term validity, SDK/checkRevoked, Rules, actual expiry, propagation time or fault recovery.

Subject: `b9592f50c07bcac36b387dfa3baa4bbfe0bf328a6499c4e1855e541400b63e81`. Recomputed from the complete recheck receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `fe7d57f0c1c7f9ac14639c472368dc8f98dda70b`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-11.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Approved observation | Corrected local / saved production |
| --- | --- |
| baseline-a-signin | Identical semantic projection; elapsedMs excluded |
| baseline-a-id | Identical semantic projection; elapsedMs excluded |
| baseline-a-refresh | Identical semantic projection; elapsedMs excluded |
| baseline-b-signin | Identical semantic projection; elapsedMs excluded |
| baseline-b-id | Identical semantic projection; elapsedMs excluded |
| baseline-b-refresh | Identical semantic projection; elapsedMs excluded |
| disabled-a-signin | Identical semantic projection; elapsedMs excluded |
| disabled-a-id | Identical semantic projection; elapsedMs excluded |
| disabled-a-refresh | Identical semantic projection; elapsedMs excluded |
| disabled-b-signin | Identical semantic projection; elapsedMs excluded |
| disabled-b-id | Identical semantic projection; elapsedMs excluded |
| disabled-b-refresh | Identical semantic projection; elapsedMs excluded |
| reenabled-a-signin | Identical semantic projection; elapsedMs excluded |
| reenabled-a-id | Identical semantic projection; elapsedMs excluded |
| reenabled-a-refresh | Identical semantic projection; elapsedMs excluded |
| reenabled-b-signin | Identical semantic projection; elapsedMs excluded |
| reenabled-b-id | Identical semantic projection; elapsedMs excluded |
| reenabled-b-refresh | Identical semantic projection; elapsedMs excluded |

The runs use separate dedicated accounts and secret credentials. The preserved operation order does not establish that old credentials work after re-enable without prior password signin or under every ordering. Token values are not public, so independent signature verification is not established by these redacted checks.

[Approval record](../../spec/compatibility/evidence/auth-disabled-recheck/approval.json) · [Recheck receipt](../../spec/compatibility/evidence/auth-disabled-recheck/receipt.json) · [Original mismatch](auth-disabled.md).

The [recheck candidate page](auth-disabled-recheck.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these eighteen observations. The original mismatch, original production observation, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.
