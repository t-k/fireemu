# Account disable / re-enable observations

Status: candidate, not approved. Eighteen redacted observations, not raw token responses or independent signature verification.

Eighteen sequential REST route observations across baseline, disabled and re-enabled phases for target A and unaffected control B. Fixed initial ID/refresh tokens, password signin and derived-token lookup; no tenant, owned strict artifact and recorded production settings. Admin is used only for owned account state changes/readback and cleanup. No human approval, instant revocation, SDK, Rules or elapsed-expiry claim.

| Phase / account / route | Local outcome / error | Production outcome / error | Same semantic projection | Local / production elapsed ms |
| --- | --- | --- | --- | --- |
| baseline-a-signin | accepted / none | accepted / none | True | 0 / 0 |
| baseline-a-id | accepted / none | accepted / none | True | 8 / 614 |
| baseline-a-refresh | accepted / none | accepted / none | True | 12 / 929 |
| baseline-b-signin | accepted / none | accepted / none | True | 21 / 1489 |
| baseline-b-id | accepted / none | accepted / none | True | 29 / 2045 |
| baseline-b-refresh | accepted / none | accepted / none | True | 33 / 2334 |
| disabled-a-signin | refused / USER_DISABLED | refused / USER_DISABLED | True | 0 / 0 |
| disabled-a-id | refused / TOKEN_EXPIRED | refused / USER_DISABLED | False | 4 / 271 |
| disabled-a-refresh | refused / INVALID_REFRESH_TOKEN | refused / USER_DISABLED | False | 8 / 540 |
| disabled-b-signin | accepted / none | accepted / none | True | 12 / 806 |
| disabled-b-id | accepted / none | accepted / none | True | 20 / 1372 |
| disabled-b-refresh | accepted / none | accepted / none | True | 24 / 1637 |
| reenabled-a-signin | accepted / none | accepted / none | True | 0 / 0 |
| reenabled-a-id | accepted / none | accepted / none | True | 8 / 607 |
| reenabled-a-refresh | refused / INVALID_REFRESH_TOKEN | accepted / none | False | 16 / 877 |
| reenabled-b-signin | accepted / none | accepted / none | True | 20 / 1440 |
| reenabled-b-id | accepted / none | accepted / none | True | 29 / 2041 |
| reenabled-b-refresh | accepted / none | accepted / none | True | 33 / 2342 |

Review subject (unapproved): `ff502af7fc37542347394d0f28e8df1b9b1566b64a5acb496a41402f040cf3de`.

Each phase begins after sequential Admin readback of target and control (baseline after setup). Elapsed milliseconds measure request start since phase start, not server-side propagation. Requests are sequential, not simultaneous or a long-term observation schedule. Timing is retained and bounded to 120 seconds but deliberately excluded from semantic equality.

A and B use separate random accounts. Initial signin ID/refresh credentials are fixed throughout; newly returned tokens are used only for derived lookup, never substituted as future observation inputs. Baselines, every B route, and fresh A signin after re-enable must succeed. Old A credentials after re-enable are observations, not assumed restored. Unknown errors, incomplete controls or failed cleanup are not publishable.

Privileged disable/re-enable checks persisted UID ownership, flag readback and selected state preservation. The disabled flag itself is excluded from selected-state equality because it is intentionally changed; all other selected fields preserve JSON types and absence. Both accounts are deleted by Admin with UID/email absence confirmation even if A remains disabled. This is not end-user deletion coverage.

Project configuration and the recorded minimum 6 / maximum 4096 password policy are read before and after without configuration writes. API key metadata and restrictions are not independently read back. The owned artifact, profile, process identity, exit zero and listener closure are checked. No SDK checkRevoked, Rules, tenant, all-session, same-second boundary, actual expiry or injected-failure recovery claim follows.

[Receipt](../../spec/compatibility/evidence/auth-disabled/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-disabled/source-review.json). All earlier evidence and approvals remain unchanged.
