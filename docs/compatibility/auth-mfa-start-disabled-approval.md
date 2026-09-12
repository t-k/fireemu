# mfaSignIn:start on a disabled account: scoped human approval

6 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.

Six production-only observations projected without secrets from the saved 2026-09-12 run of auth-mfa-start-disabled, recorded from a committed checkout. mfaSignIn:start on an account disabled after its pending credential is accepted and returns a session; its finalize is refused USER_DISABLED; after re-enablement the same pending credential starts and finalizes; a baseline and final fresh finalize are controls; the configuration was restored with a matching whole-configuration digest and the account deleted with UID/email absence. The approval does not extend to a production/local comparison of this corpus, to TOTP, tenants, blocking functions, SDK, Rules or the credential's expiry.

Subject: `e0fdb84012734f99533f84e7fab173d26e1f0f0a9112f4703d990f1a968df442`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `aef95ad3e6f623d6ce8263f52ce20791b67afe68`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| baseline-fresh-finalize | control | accepted / none |
| disabled-start | diagnostic | accepted / none |
| disabled-finalize | diagnostic | refused / USER_DISABLED |
| reenabled-start | diagnostic | accepted / none |
| reenabled-finalize | diagnostic | accepted / none |
| final-fresh-finalize | control | accepted / none |

Approved as the observed outcome under the recorded conditions: mfaSignIn:start on a disabled account is accepted and the disabled state is enforced at finalize (USER_DISABLED), and the held pending credential survives re-enablement. fireemu was corrected to match (GAP-AUTH-005); its local comparison is approved separately.

[Approval record](../../spec/compatibility/evidence/auth-mfa-start-disabled/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json) · [Candidate page](auth-mfa-start-disabled.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these six observations. The private run, the source mapping and every earlier approval remain unchanged.
