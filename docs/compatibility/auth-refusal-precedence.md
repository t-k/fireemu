# Precedence of overlapping refusals

Status: candidate, not approved. Nine redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local order is enumerated separately in `tools/auth-refusal-precedence/README.md`.

Nine sequential REST observations in production only: fresh phone MFA completions for A and B; a client accounts:update with A's baseline ID token altered by one signature character, a sentinel custom claim and a sentinel photo URL, sent before any disable and followed by a privileged readback; then, with a pending credential and an SMS session held by each account, both accounts disabled and read back, the held credential and session of A finalized with a fixed wrong code and those of B with the correct code; both accounts re-enabled and read back and the same held credentials and sessions finalized with the correct code; fresh completions for A and B. Phone MFA with test phone numbers, no tenant, no blocking function, one run. The oracle configuration was changed for the run and restored with a digest comparison. Admin is used for owned account setup, the disable and re-enable transitions, readback and cleanup. No human approval, no local artifact comparison, no claim about a valid token with a privileged field, about mfaSignIn:start on a disabled account, about the pending credential's expiry, TOTP, SDK or Rules.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-a-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 5856 |
| baseline-b-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 7087 |
| invalid-token-admin-field-update | diagnostic | refused / INVALID_ID_TOKEN | none | 8790 |
| disabled-a-wrong-code-finalize | diagnostic | refused / INVALID_CODE | none | 12535 |
| disabled-b-correct-code-finalize | diagnostic | refused / USER_DISABLED | none | 12815 |
| reenabled-a-held-finalize | diagnostic | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 14960 |
| reenabled-b-held-finalize | diagnostic | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 15564 |
| final-a-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 16828 |
| final-b-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 18044 |

Tampered ID token with an administrator-only field, before any disable: **refused / INVALID_ID_TOKEN**; A unchanged on readback: True. Disabled account, held session, wrong code (A): **refused / INVALID_CODE**. Disabled account, held session, correct code (B): **refused / USER_DISABLED**. The same held credentials and sessions after re-enablement: A accepted / none, B accepted / none.

Review subject (unapproved): `6c76f862a7b7a2d9ad557ae43d03d3787221089a76e999ae03478e20069fe3c4`.

A and B differ only in the code they present while disabled, on sessions started before the disable and read back afterwards, so the two rows together show which of the code and the account state is checked first. The re-enabled rows reuse the same pending credential and session, so they show whether each refusal consumed them. The tampered-token row carries a real ID token of A with one signature character changed inside the signature, so only an invalid signature and a privileged field overlap; the fields were chosen so that an acceptance could not have changed A's verified email, factor enrollment or ownership marker. Elapsed milliseconds are cumulative time from the recorder's measurement origin (set before account setup), sampled when each row is recorded after its checks; they are neither request latency nor time since the disable, and are excluded from semantic equality.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, two test phone numbers with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored in the recorder's final step before the accounts were deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. Both accounts were deleted with UID and email absence confirmation. The run started from a committed checkout of every probe tree.

Recorded with the recorder files at commit `7d6d6431ef4727d17989bd8834e1833814dc7922` while the repository was at `7d6d6431ef4727d17989bd8834e1833814dc7922`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `fb4a6ca1a264a3e8b528f867439eb51e3bc97cb4`. The observation itself was not re-run.

This does not show what a valid token with a privileged field does, what mfaSignIn:start answers for a disabled account, how an expired pending credential ranks against a valid code, or anything about TOTP, tenants, blocking functions, SDK or Rules.

[Receipt](../../spec/compatibility/evidence/auth-refusal-precedence/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-refusal-precedence/source-review.json). All earlier evidence and approvals remain unchanged.
