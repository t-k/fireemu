# MFA pending credential across an explicit revocation: scoped human approval

8 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.

Eight production-only observations projected without secrets from the saved 2026-09-11 run of auth-pending-revocation revision 1. Explicit validSince update through privileged accounts:update with readback, phone MFA with test phone numbers, no tenant, no blocking hook, the recorded operation order and a single run. The held pending credential of target A, issued before the update and never completed, was presented after the update: start and finalize were accepted, the returned ID token's auth_time was at or after the set validSince, lookup and refresh succeeded. Baseline and fresh completions for A and control B, the recorded configuration restore with a matching digest, and Admin deletion with UID/email absence are included. The approval does not extend to a production/local comparison of this corpus, revocation propagation time, refusal of a pre-update refresh token, password changes, other MFA methods, tenants, blocking hooks, SDK checkRevoked, Rules or credential expiry.

Subject: `c6ce38ac6a05b969cdbbf516e77a1fc386e73cb221301d53f98c2c45029a0eb7`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `3a68ff3d94ce0b2f185fafb32a25bc2ed3f02e36`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-11.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving the recorded observation does not authorize new production operations.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| baseline-a-fresh-finalize | control | accepted / none |
| baseline-b-fresh-finalize | control | accepted / none |
| revoked-a-held-start | diagnostic | accepted / none |
| revoked-a-held-finalize | diagnostic | accepted / none |
| revoked-a-held-lookup | diagnostic | accepted / none |
| revoked-a-held-refresh | diagnostic | accepted / none |
| revoked-a-fresh-finalize | control | accepted / none |
| revoked-b-fresh-finalize | control | accepted / none |

The held credential rows are approved as the observed outcome under the recorded conditions, not as a rule about revocation. Token values are not public, so independent signature verification is not established by these redacted checks. The two-second wait preceded the validSince update; the interval between the update and the retry was not measured.

[Approval record](../../spec/compatibility/evidence/auth-pending-revocation/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-pending-revocation/receipt.json) · [Candidate page](auth-pending-revocation.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these eight observations. The private run, the earlier unapproved candidate in history, the source mapping and every earlier approval remain unchanged.
