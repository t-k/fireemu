# Account disable and re-enable: corrected artifact recheck

Candidate only: 18 redacted REST observations match between the corrected local artifact and the retained production observation. No approval is granted or inherited.

Review subject (unapproved): `b9592f50c07bcac36b387dfa3baa4bbfe0bf328a6499c4e1855e541400b63e81`.
Local runtime source: `5e63d0410c315fdfa118f1f047bbc267cb80698c`; artifact SHA-256: `c4b012d8b2ba2adb25d8cd5ae298025bd6b1ae5ef6bbfd5a765d339ce96ef067`.
Local capture: `2026-09-10T15:42:21.079143+00:00`. Production capture: `2026-09-10T15:28:06.202043+00:00` (reused unchanged; not a new production run).

| Phase / account / route | Both targets | Error | Local / production elapsed ms |
| --- | --- | --- | --- |
| baseline-a-signin | accepted | none | 0 / 0 |
| baseline-a-id | accepted | none | 5 / 614 |
| baseline-a-refresh | accepted | none | 7 / 929 |
| baseline-b-signin | accepted | none | 13 / 1489 |
| baseline-b-id | accepted | none | 18 / 2045 |
| baseline-b-refresh | accepted | none | 21 / 2334 |
| disabled-a-signin | refused | USER_DISABLED | 0 / 0 |
| disabled-a-id | refused | USER_DISABLED | 2 / 271 |
| disabled-a-refresh | refused | USER_DISABLED | 5 / 540 |
| disabled-b-signin | accepted | none | 8 / 806 |
| disabled-b-id | accepted | none | 13 / 1372 |
| disabled-b-refresh | accepted | none | 16 / 1637 |
| reenabled-a-signin | accepted | none | 0 / 0 |
| reenabled-a-id | accepted | none | 5 / 607 |
| reenabled-a-refresh | accepted | none | 10 / 877 |
| reenabled-b-signin | accepted | none | 15 / 1440 |
| reenabled-b-id | accepted | none | 21 / 2041 |
| reenabled-b-refresh | accepted | none | 23 / 2342 |

Scope: tenant-free REST, local strict profile, recorded production authentication and password-policy settings. A is disabled then re-enabled; B is the independent unaffected control. Fixed original ID and refresh tokens are reused, and successful refresh results include derived ID-token lookup. The three disabled-A routes each return USER_DISABLED. All other 15 observations succeed.

Disable-only strict updates retain existing credentials but refuse their use while disabled. Password/email changes and explicit revocation remain independent; re-enabling does not undo them. The runtime unit tests cover a two-second separation between issuance and disablement; this record does not establish same-second boundary behavior or universal propagation timing.

The two dedicated accounts have UID/email absence confirmation. The owned local process exited zero with listeners closed. Production settings were not read back again, and no new production requests were made for this recheck. The original captures read project configuration and password policy before and after execution, but did not independently read API-key restrictions. Source references remain locator mappings, not newly hash-bound full-page reviews.

Elapsed times are bounded request-start offsets from sequential phase readback, not exact server-side state-change times. Only elapsedMs is excluded from semantic equality. These separate runs use the same input classifications and controls, not identical secret credentials. No claim covers long-term validity, expiry, all session series, SDK/checkRevoked, Rules, fault recovery or every disablement path.

[New receipt](../../spec/compatibility/evidence/auth-disabled-recheck/receipt.json) · [Original mismatch](auth-disabled.md) · [Unchanged source mapping](../../spec/compatibility/evidence/auth-disabled/source-review.json). Original observations and previous approvals remain unchanged.
