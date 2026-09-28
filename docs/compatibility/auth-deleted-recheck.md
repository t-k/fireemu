# Deleted-account credentials: corrected artifact recheck

Candidate only: 12 redacted REST observations match between the corrected local artifact and the retained production observation. No approval is granted or inherited.

Review subject (unapproved): `538747b5e8e9fc3be27952255019fe1a147b766d12c919e8b8c1aef865744174`.
Local runtime source: `cff2b3890f83c18839272950038bb99427392d02`; artifact SHA-256: `8f39ae7fd00f25028e317dc716ce74545364f1098de6c3a618d1c9cc2550c530`.
Local capture: `2026-09-10T23:04:09.440463+00:00`. Production capture: `2026-09-10T16:06:59.559810+00:00` (reused unchanged; not a new production run).

| Phase / account / route | Both targets | Error | Local / production elapsed ms |
| --- | --- | --- | --- |
| baseline-a-signin | accepted | none | 0 / 0 |
| baseline-a-id | accepted | none | 5 / 629 |
| baseline-a-refresh | accepted | none | 8 / 928 |
| baseline-b-signin | accepted | none | 13 / 1493 |
| baseline-b-id | accepted | none | 18 / 2092 |
| baseline-b-refresh | accepted | none | 21 / 2378 |
| deleted-a-signin | refused | INVALID_LOGIN_CREDENTIALS | 0 / 0 |
| deleted-a-id | refused | USER_NOT_FOUND | 2 / 275 |
| deleted-a-refresh | refused | USER_NOT_FOUND | 5 / 591 |
| deleted-b-signin | accepted | none | 7 / 895 |
| deleted-b-id | accepted | none | 12 / 1513 |
| deleted-b-refresh | accepted | none | 15 / 1775 |

Scope: tenant-free REST, local strict profile and recorded production authentication and password-policy settings. A is deleted using its own fixed ID token; B is the independent unaffected control. Each phase observes password signin, fixed original ID-token lookup, then fixed original refresh-token use and derived lookup. Deleted A returns INVALID_LOGIN_CREDENTIALS for signin and USER_NOT_FOUND for lookup and refresh. All other nine observations succeed.

The correction preserves validation-before-user-lookup ordering and distinguishes known deleted refresh credentials from unknown input using rejection-only digests. It does not accept deleted credentials or broaden other ID-token API error mappings. Local unit/model tests cover refresh UID-reuse rejection and snapshot/reset handling; those are not new production account-recreation observations. [Retention and verification details](../../tools/auth-deleted-recheck/README.md).

The two dedicated accounts have UID/email absence confirmation. The owned local process exited zero with listeners closed. Production settings were not read back again, and no new production requests were made for this recheck. The original captures read project configuration and password policy before and after execution, but did not independently read API-key restrictions. Source references remain locator mappings, not newly hash-bound full-page reviews.

Elapsed times are bounded request-start offsets from sequential phase readback, not exact server-side state-change times. Only elapsedMs is excluded from semantic equality. These separate runs use the same input classifications and controls, not identical secret credentials. No claim covers long-term validity, expiry, all session series, SDK/checkRevoked, Rules, fault recovery or every deletion path or account-recreation sequence.

[New receipt](../../spec/compatibility/evidence/auth-deleted-recheck/receipt.json) · [Original mismatch](auth-deleted.md) · [Unchanged source mapping](../../spec/compatibility/evidence/auth-deleted/source-review.json). Original observations and previous approvals remain unchanged.
