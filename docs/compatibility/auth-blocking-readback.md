# Hook-applied disable: readback timing

Status: candidate, not approved. Eleven redacted production observations on one run's time axis. No local artifact comparison is part of this record.

Eleven sequential REST observations in production only with the disabling beforeSignIn function (the one recorded in auth-blocking-disable) deployed for the run. Two claimed accounts X and Y are refused on sign-in; the disabled flag is read back through privileged lookup for X before, immediately after, five and thirty seconds after the refusal, and for Y only after thirty seconds with no earlier read; a control Z signs in first and last. Readback rows record the flag as seen with the seconds since the refusal. The function was removed and the trigger registration restored with a digest comparison; the three accounts were deleted with absence confirmation. No MFA, phone or SMS configuration was touched. No human approval, no local artifact comparison in this record, and no claim beyond these points on one run's time axis.

| Case | Basis | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- |
| control-z-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 7238 |
| x-readback-before | readback | accepted / none | disabledPersisted=False, secondsSinceRefusal=None | 7583 |
| x-first-signin | diagnostic | refused / USER_DISABLED | none | 7915 |
| x-readback-immediate | readback | accepted / none | disabledPersisted=False, secondsSinceRefusal=0 | 8234 |
| x-readback-after-5s | readback | accepted / none | disabledPersisted=False, secondsSinceRefusal=5 | 13608 |
| x-readback-after-30s | readback | accepted / none | disabledPersisted=False, secondsSinceRefusal=31 | 38944 |
| x-second-signin | diagnostic | refused / USER_DISABLED | none | 39301 |
| y-first-signin | diagnostic | refused / USER_DISABLED | none | 39659 |
| y-readback-after-30s-unread | readback | accepted / none | disabledPersisted=False, secondsSinceRefusal=30 | 69984 |
| y-second-signin | diagnostic | refused / USER_DISABLED | none | 70337 |
| control-z-final-signin | control | accepted / none | derivedLookup=True, emailMatches=True, expiryIsPositiveInteger=True, expiryMatchesOneHour=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, uidMatches=True | 70942 |

Disabled flag as read back: x-readback-before: False at Nones; x-readback-immediate: False at 0s; x-readback-after-5s: False at 5s; x-readback-after-30s: False at 31s; y-readback-after-30s-unread: False at 30s.

Review subject (unapproved): `81dae6d26f525a31e121abb87669e875026696f50ce44a223fc9c396c9806b9b`.

The seconds are measured by the recorder between the refused sign-in's response and the readback request; they are not server-side propagation measurements. A readback that reads false is a fact about that moment on that account, not a rule; the gap ledger (GAP-AUTH-001) names what follows from the pattern across the five points.

Recorded with the recorder and function files at commit `512b043559ecce10a2614c5cf3ea43f816dab347` while the repository was at `483e157937a267e6be07ae800badb390406d7d56`. Re-evaluated at publication with the contract at commit `483e157937a267e6be07ae800badb390406d7d56`. Elapsed milliseconds are cumulative from the recorder's measurement origin and excluded from semantic equality, as are the measured seconds.

[Receipt](../../spec/compatibility/evidence/auth-blocking-readback/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-blocking-readback/source-review.json). All earlier evidence and approvals remain unchanged.
