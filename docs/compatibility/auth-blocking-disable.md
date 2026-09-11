# Blocking function that disables the account

Status: candidate, not approved. Twelve redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus; the local behavior is pinned separately by the `pending_retry` regressions.

Twelve sequential REST observations in production only with a first-generation beforeSignIn blocking function deployed for the run: it answers disabled: true for accounts carrying a dedicated custom claim and passes every other sign-in through. Target C (no second factor, claim) signs in with a password; target A (phone factor, claim) completes a phone MFA finalize; control B (phone factor, no claim) completes before and after. Any returned tokens are used for lookup and refresh, the disabled flag is read back through Admin, and a second sign-in follows. Phone MFA with test phone numbers, no tenant, one function shape, one run. The function was removed and the configuration, including the trigger registration, restored with a digest comparison. Admin is used for owned account setup, readback and cleanup. No human approval, no local artifact comparison, no rejecting function or beforeCreate, and no propagation claim about the persisted flag.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-b-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 8571 |
| hook-c-first-signin | diagnostic | refused / USER_DISABLED | none | 8926 |
| hook-c-token-lookup | diagnostic | skipped / none | none | 8927 |
| hook-c-token-refresh | diagnostic | skipped / none | none | 8927 |
| hook-c-disabled-readback | control | accepted / none | disabledPersisted=False | 9258 |
| hook-c-second-signin | diagnostic | refused / USER_DISABLED | none | 9627 |
| hook-a-first-finalize | diagnostic | refused / USER_DISABLED | none | 10549 |
| hook-a-token-lookup | diagnostic | skipped / none | none | 10549 |
| hook-a-token-refresh | diagnostic | skipped / none | none | 10549 |
| hook-a-disabled-readback | control | accepted / none | disabledPersisted=True | 11007 |
| hook-a-second-signin | diagnostic | refused / USER_DISABLED | none | 11312 |
| final-b-fresh-finalize | control | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 12614 |

Hook outcomes: password sign-in of the claimed account **refused** (USER_DISABLED), phone MFA finalize of the claimed account **refused** (USER_DISABLED). Disabled flag read back through Admin immediately afterwards: C False, A True. Second sign-ins: C refused, A refused.

Review subject (unapproved): `5703ed488024407fefbaf531a12ae43c01b48093903a64bf3ce775bdbb067034`.

The function was deployed from the checked-in source in `tools/auth-blocking-disable/function` (first-generation API, because Identity Platform registers and signs for the cloudfunctions.net URI that the second-generation identity handler rejects). It disables only accounts carrying the claim set on A and C through privileged accounts:update; B never carries it. The trigger registration was read back before the observations and is absent in the restore readback. Elapsed milliseconds are cumulative time from the recorder's measurement origin (set before account setup), sampled when each row is recorded after its checks; they are neither request latency nor hook latency, and are excluded from semantic equality.

The oracle project had MFA disabled, no phone sign-in, an empty SMS region allowlist and no blocking triggers. For the run, the function was deployed and phone MFA, two test phone numbers with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled. The function was deleted (absence in the functions listing is the authority) and the recorded values were restored in the recorder's final step; the readback matched and the whole-configuration digest equaled the pre-run digest. All three accounts were deleted with UID and email absence confirmation.

Recorded with the recorder and function files at commit `08002f594930ca29e3e414bc8fcf4413f657a0a7` while the repository was at `7ba905d3f98085430ef38c590b8c57c2ec0d07b5`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `69fa048fb6a212f708784e7829c7c05b98bcab02`. The observation itself was not re-run.

Whether the disable persisted on the record differed between the two claimed accounts at the immediate readback in this single run; no second readback or wait was performed, so nothing about propagation follows. This does not show what a rejecting function, a beforeCreate function, other response fields, tenants or SDK behavior do.

[Receipt](../../spec/compatibility/evidence/auth-blocking-disable/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-blocking-disable/source-review.json). All earlier evidence and approvals remain unchanged.
