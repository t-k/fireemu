# Deleted-account credentials recheck: scoped human approval

12 observations verified and approved within this limited scope as a recheck of the corrected local artifact against saved production observations. This is not a new production run or a claim of complete Auth compatibility.

Twelve observations rechecked on the recorded corrected local artifact against unchanged saved production observations. No tenant, local strict profile and recorded production authentication/password-policy settings. Target A is deleted using its own fixed ID token; independent B is the unaffected successful control. Each phase follows the recorded order: password signin, fixed original ID-token lookup, then fixed original refresh-token exchange; successful issued tokens are used for lookup. Approval includes selected state checks, deletion and UID/email absence, remaining owned-account cleanup and owned process termination. Only elapsedMs is excluded from semantic comparison: deleted-A signin returns INVALID_LOGIN_CREDENTIALS, deleted-A ID lookup and refresh return USER_NOT_FOUND, and the remaining nine succeed. This is not a new production run. Approval explicitly excludes identifier-based accounts:lookup authorization; its authentication/authorization bypass is a separate required fix. No claim covers all credential series, ID-token UID reuse, SDK/checkRevoked, Rules, actual expiry, propagation time or fault recovery.

Subject: `538747b5e8e9fc3be27952255019fe1a147b766d12c919e8b8c1aef865744174`. Recomputed from the complete recheck receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `7e9b327acbede270687cbe76164bef098d32b43b`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-11.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication.

| Approved observation | Corrected local / saved production |
| --- | --- |
| baseline-a-signin | Identical semantic projection; elapsedMs excluded |
| baseline-a-id | Identical semantic projection; elapsedMs excluded |
| baseline-a-refresh | Identical semantic projection; elapsedMs excluded |
| baseline-b-signin | Identical semantic projection; elapsedMs excluded |
| baseline-b-id | Identical semantic projection; elapsedMs excluded |
| baseline-b-refresh | Identical semantic projection; elapsedMs excluded |
| deleted-a-signin | Identical semantic projection; elapsedMs excluded |
| deleted-a-id | Identical semantic projection; elapsedMs excluded |
| deleted-a-refresh | Identical semantic projection; elapsedMs excluded |
| deleted-b-signin | Identical semantic projection; elapsedMs excluded |
| deleted-b-id | Identical semantic projection; elapsedMs excluded |
| deleted-b-refresh | Identical semantic projection; elapsedMs excluded |

The runs use separate dedicated accounts and secret credentials. Token values are not public, so independent signature verification is not established by these redacted checks. The approval does not assert that identifier-based lookup is authorized correctly; that boundary requires a separate runtime correction.

[Approval record](../../spec/compatibility/evidence/auth-deleted-recheck/approval.json) · [Recheck receipt](../../spec/compatibility/evidence/auth-deleted-recheck/receipt.json) · [Original mismatch](auth-deleted.md).

The [recheck candidate page](auth-deleted-recheck.md) remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these twelve observations. The original mismatch, original production observation, source mapping and earlier approvals remain unchanged. Historical validation is not a rerun of earlier behaviors on the latest runtime.
