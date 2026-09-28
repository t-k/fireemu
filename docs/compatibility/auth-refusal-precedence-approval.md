# Precedence of overlapping refusals: scoped human approval

9 production-only observations verified and approved within this limited scope. This is not a new production run, not a production/local comparison, and not a claim of complete Auth compatibility.

Nine production-only observations projected without secrets from the saved 2026-09-12 run of auth-refusal-precedence revision 1, recorded from a committed checkout with the recorder at 7d6d6431. The verification code is checked before the account state (a disabled account's held SMS session is refused INVALID_CODE with a wrong code and USER_DISABLED with the correct code); the same held pending credentials and sessions complete after re-enablement, so neither refusal consumes them; a client accounts:update carrying a tampered ID token and an administrator-only field is refused INVALID_ID_TOKEN with nothing applied on readback. Fresh completions for A and B bound the run, the configuration was restored with a matching whole-configuration digest, and both accounts were deleted with UID/email absence. The approval does not extend to a production/local comparison of this corpus, to INVALID_ID_TOKEN always winning for any invalid-token condition, to INVALID_CODE always winning for any MFA refusal, to a valid active token with an administrator-only field, to mfaSignIn:start on a disabled account, to an expired pending credential, to TOTP, tenants, SDK or Rules.

Subject: `6c76f862a7b7a2d9ad557ae43d03d3787221089a76e999ae03478e20069fe3c4`. Recomputed from the complete receipt; this approval cannot transfer to a changed subject.

Reviewed commit: `ae4ec3cdca687e1bb780916957005e6bcb67778d`. Reviewer: `github:t-k (id:426779)`. Approval date: 2026-09-12.

This records the user's explicit decision, not a cryptographic signature or independent identity authentication. The source mapping's execution approval stays not-granted: approving the recorded observation does not authorize new production operations.

| Approved observation | Basis | Recorded outcome |
| --- | --- | --- |
| baseline-a-fresh-finalize | control | accepted / none |
| baseline-b-fresh-finalize | control | accepted / none |
| invalid-token-admin-field-update | diagnostic | refused / INVALID_ID_TOKEN |
| disabled-a-wrong-code-finalize | diagnostic | refused / INVALID_CODE |
| disabled-b-correct-code-finalize | diagnostic | refused / USER_DISABLED |
| reenabled-a-held-finalize | diagnostic | accepted / none |
| reenabled-b-held-finalize | diagnostic | accepted / none |
| final-a-fresh-finalize | control | accepted / none |
| final-b-fresh-finalize | control | accepted / none |

The diagnostic rows are approved as the observed outcome under the recorded conditions, not as a general precedence rule. The finalize order (code before account state) and the survival of the held credentials across disable and re-enablement match fireemu. The tampered-token row diverges: production verifies the ID token before judging the administrator-only field, while fireemu rejects the field first; the fireemu correction and its local comparison are separate steps. The approval does not establish INVALID_ID_TOKEN for any other invalid-token condition, nor the exact error for a valid token with an administrator-only field.

[Approval record](../../spec/compatibility/evidence/auth-refusal-precedence/approval.json) · [Receipt](../../spec/compatibility/evidence/auth-refusal-precedence/receipt.json) · [Candidate page](auth-refusal-precedence.md).

The candidate page remains acquisition-time history. This separate approval supersedes its pending status only for this subject and these nine observations. The private run, the discarded run 1, the source mapping and every earlier approval remain unchanged.
