# Deleted-account credential observations

Status: candidate, not approved. Twelve redacted observations, not raw token responses or independent signature verification.

Twelve sequential REST route observations before and after end-user deletion of target A, with independent unaffected account B. Fixed initial ID/refresh tokens, password signin and derived-token lookup; no tenant, owned strict artifact and recorded production settings. Admin is used for owned account readback and cleanup only. No human approval, universal propagation, SDK, Rules or elapsed-expiry claim.

| Phase / account / route | Local outcome / error | Production outcome / error | Same semantic projection | Local / production elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-a-signin | accepted / none | accepted / none | True | 0 / 0 |
| baseline-a-id | accepted / none | accepted / none | True | 5 / 629 |
| baseline-a-refresh | accepted / none | accepted / none | True | 8 / 928 |
| baseline-b-signin | accepted / none | accepted / none | True | 14 / 1493 |
| baseline-b-id | accepted / none | accepted / none | True | 19 / 2092 |
| baseline-b-refresh | accepted / none | accepted / none | True | 22 / 2378 |
| deleted-a-signin | refused / INVALID_LOGIN_CREDENTIALS | refused / INVALID_LOGIN_CREDENTIALS | True | 0 / 0 |
| deleted-a-id | refused / INVALID_ID_TOKEN | refused / USER_NOT_FOUND | False | 2 / 275 |
| deleted-a-refresh | refused / INVALID_REFRESH_TOKEN | refused / USER_NOT_FOUND | False | 5 / 591 |
| deleted-b-signin | accepted / none | accepted / none | True | 8 / 895 |
| deleted-b-id | accepted / none | accepted / none | True | 14 / 1513 |
| deleted-b-refresh | accepted / none | accepted / none | True | 16 / 1775 |

Review subject (unapproved): `04f8ac7d63ee9e34eab54057a03c876dce2d75bc8e0e5eb0430b1f7cb5faedc1`.

The deleted phase begins after successful end-user deletion, UID/email absence and control readback (baseline after setup). Elapsed milliseconds measure request start since phase start, not server-side propagation. Requests are sequential, not simultaneous or a long-term observation schedule. Timing is retained and bounded to 120 seconds but deliberately excluded from semantic equality.

A and B use separate random accounts. Initial signin ID/refresh credentials are fixed throughout; newly returned tokens are used only for derived lookup, never substituted as future observation inputs. Baselines and every B route must succeed. All three deleted-A routes must refuse; their exact bounded errors remain independently visible and are compared, not assumed equal. Unknown errors, incomplete controls or failed cleanup are not publishable.

Before deletion, persisted UID is re-read and independently looked up to confirm ownership. A is deleted through accounts:delete with its own fixed ID token, followed by separate UID and email absence checks. B preserves selected account fields, including JSON types and absence. Finally, any remaining owned accounts are cleaned up with both absence checks. This is not a claim about all account state, token signatures or fault-injected recovery.

Project configuration and the recorded minimum 6 / maximum 4096 password policy are read before and after without configuration writes. API key metadata and restrictions are not independently read back. The owned artifact, profile, process identity, exit zero and listener closure are checked. No SDK checkRevoked, Rules, tenant, all-session, recreated-account, actual expiry or injected-failure recovery claim follows. Source mappings provide reviewed URLs and section locators, not a new hash-bound full-body page review.

[Receipt](../../spec/compatibility/evidence/auth-deleted/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-deleted/source-review.json). All earlier evidence and approvals remain unchanged.
