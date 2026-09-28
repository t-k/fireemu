# Held MFA pending credential across client-password-change: scoped human approval

7 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.

Seven production-only observations projected without secrets from the saved 2026-09-12 run of the client-password-change trigger (auth-pending-trigger), recorded from a committed checkout. A pending MFA credential and SMS session held from before the transition are presented after it; whether they still start and finalize is the observed outcome, with a baseline and a final fresh completion as controls, the configuration restored with a matching whole-configuration digest, and the account deleted with UID/email absence. The approval does not extend to a production/local comparison of this corpus, to any other trigger, to a rule about revocation, to tenants, SDK or Rules.

Subject: `698884037cb56f6ec50d5656fb57b490512c26556eae58c35e7147bd581aa1d6`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `2a05cf20ec01c4e62a6a1d5d497df2aac51b101f`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving the recorded observation does not authorize new production operations.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none |
| trigger | diagnostic | accepted / none |
| held-start | diagnostic | accepted / none |
| held-finalize | diagnostic | accepted / none |
| held-lookup | diagnostic | accepted / none |
| held-refresh | diagnostic | accepted / none |
| final-fresh-finalize | control | accepted / none |

The held rows are approved as the observed outcome under the recorded conditions and this trigger only, not as a rule about revocation. Token values are not public, so independent signature verification is not established by these redacted checks.

[Approval record](../../spec/compatibility/evidence/auth-pending-trigger-client-password-change/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-pending-trigger-client-password-change/receipt.json) · [Candidate page](auth-pending-trigger-client-password-change.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these seven observations. The private run, the source mapping and every earlier approval remain unchanged.
