# Administrative updates to a disabled account

Status: candidate, not approved. Ten redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus; the local behavior is pinned separately by the `pending_retry` regressions.

Ten sequential REST observations in production only: password sign-ins of target A and control B, then A is disabled through privileged accounts:update and read back; while disabled, an administrative password replacement and an administrative photo update are attempted on A (whether tokens are returned is the observation; any returned tokens are tried for lookup and refresh), A signs in with the new password, B signs in; A is re-enabled and read back, and both sign in again. No tenant, no configuration change (the configuration and the recorded password policy are read before and after and must be unchanged), a single run. Admin is used for owned account setup, the disable and re-enable transitions, the two updates, readback and cleanup. No human approval, no local artifact comparison, and no claim about other update fields, tenants, SDK or Rules.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-a-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 3979 |
| baseline-b-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 4583 |
| disabled-a-password-update | diagnostic | accepted / none | localIdMatches=True, noError=True, readbackApplied=True, tokensReturned=False | 6720 |
| disabled-a-update-token-lookup | diagnostic | skipped / none | none | 6720 |
| disabled-a-update-token-refresh | diagnostic | skipped / none | none | 6720 |
| disabled-a-photo-update | diagnostic | accepted / none | localIdMatches=True, noError=True, readbackApplied=True, tokensReturned=False | 7459 |
| disabled-a-signin | diagnostic | refused / USER_DISABLED | none | 7756 |
| disabled-b-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 8388 |
| reenabled-a-signin | diagnostic | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 10409 |
| reenabled-b-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 11006 |

Administrative password replacement of the disabled account: **accepted** (no error), tokens returned: False. Administrative photo update: **accepted** (no error), tokens returned: False. The disabled account's own sign-in with the new password: refused / USER_DISABLED; after re-enablement: accepted.

Review subject (unapproved): `c5edbe9850fc52c66c666ca0c62961af3c4ad214fc074a950380c592960560fd`.

The two administrative updates carry `readbackApplied`, which requires the update to be visible through privileged lookup with the account still disabled and (for the password update) the selected non-photo fields unchanged. `tokensReturned` records whether the update response carried an ID token; the token rows run exactly when it did. Elapsed milliseconds are cumulative time from the recorder's measurement origin (set before account setup), sampled when each row is recorded after its checks; they are neither request latency nor time since the disable, and are excluded from semantic equality.

Recorded with the recorder files at commit `8dddb9736d64e9acc68fc2e73f2483ef98be43ec` while the repository was at `8dddb9736d64e9acc68fc2e73f2483ef98be43ec`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `0635fa18bcef41fcc687503fc40fbb19e8d61f81`. The observation itself was not re-run.

This does not show what other update fields do on a disabled account, what a self-service update by a disabled user does, tenant behavior, or SDK and Rules behavior.

[Receipt](../../spec/compatibility/evidence/auth-disabled-admin-update/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-disabled-admin-update/source-review.json). All earlier evidence and approvals remain unchanged.
