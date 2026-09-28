# MFA pending credential lifetime: revision 2 boundary candidates

Status: candidate, not approved. Ten redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the owned local comparison is published separately.

Ten sequential REST observations in production: fresh phone MFA completion controls surround independent pending credentials held untouched for 600, 1800, 3300 and 3900 seconds, each followed by start and, if accepted, finalize with a fresh SMS session. Six owned accounts, one test phone number, no tenant or blocking function, one recorded configuration and one run. The largest fully verified success is an observed survival lower bound. Refusals retain measured pending-age intervals and separate start/finalize stages; any boundary candidate assumes equivalent account conditions and monotonic usability and does not prove age-caused expiry. No lifetime upper bound, exact TTL, error precedence, universal account guarantee or result approval is asserted. Configuration recovery and account absence are verified. Refresh-token presence is not a refresh exchange. The expired-pending/independently-valid-code residual remains unobserved.

| Case | Basis | Pending age (s) | Outcome / error | Checks | Elapsed ms |
| --- | --- | --- | --- | --- | --- |
| baseline-fresh-finalize | control | [0.2838141249958426, 0.8797862918581814] | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 13000 |
| age-600s-start | diagnostic | [600.0100229999516, 600.6611048749182] | refused / INVALID_MFA_PENDING_CREDENTIAL | none | 613661 |
| age-600s-finalize | diagnostic | - | skipped | none | 613662 |
| age-1800s-start | diagnostic | [1800.0076130421367, 1800.631279333029] | refused / INVALID_MFA_PENDING_CREDENTIAL | none | 1813967 |
| age-1800s-finalize | diagnostic | - | skipped | none | 1813967 |
| age-3300s-start | diagnostic | [3300.0100262498017, 3300.628215875011] | refused / INVALID_MFA_PENDING_CREDENTIAL | none | 3314267 |
| age-3300s-finalize | diagnostic | - | skipped | none | 3314267 |
| age-3900s-start | diagnostic | [3900.0100315001328, 3900.6344127499033] | refused / INVALID_MFA_PENDING_CREDENTIAL | none | 3914592 |
| age-3900s-finalize | diagnostic | - | skipped | none | 3914592 |
| final-fresh-finalize | control | [0.2759592500515282, 0.871251542121172] | accepted / none | claimEmailMatches=True, claimSubMatches=True, derivedLookup=True, idTokenPresent=True, noError=True, refreshTokenPresent=True, secondFactorClaim=True | 3915760 |

Sampled ages: 600, 1800, 3300, 3900 s. Verified usable: none. Refused: 600 s (INVALID_MFA_PENDING_CREDENTIAL), 1800 s (INVALID_MFA_PENDING_CREDENTIAL), 3300 s (INVALID_MFA_PENDING_CREDENTIAL), 3900 s (INVALID_MFA_PENDING_CREDENTIAL). Indeterminate (accepted without a verified token): none. This establishes no verified success at any sampled age. A refused age records its error, but this revision does not prove a refusal is due to expiry, so it asserts no lifetime upper bound.

Start accepted at target ages: []. Nonmonotonic observations: False. Boundary candidates: `[]`. Candidate upper endpoints use the refused request interval upper endpoint, never its target age. Age-caused expiry and a shared upper bound remain unestablished.

Privileged HTTP requests: 61; refresh attempts by phase: `{"observation": 1, "recovery": 1}`. Each privileged project/configuration/account request has recorded verified expiry and remaining validity. Refresh, tokeninfo and preflight CLI operations are phase-budgeted; acquisition age alone is not expiry evidence.

Review subject (unapproved): `fa7a8be261077f7f670965297772d43afae793dc131d010b1ce32efb87e28f0b`.

Each pending credential was obtained near a common origin and left untouched until its own diagnostic, so no intermediate access could extend it; the SMS session was opened fresh at the diagnostic, so its age at finalize is recorded as an interval near zero while only the pending age grows. A sampled age is counted usable only when its start returned a session and its finalize both succeeded and passed every identity check; an accepted finalize with a missing or unverifiable token is recorded but counts as indeterminate, not usable. A refused start records its error and skips its finalize. The pending age at start and the session age at finalize are kept in a separate timing region on each row, saved on refusal too, and excluded from semantic equality along with the elapsed milliseconds, since they vary across runs and clocks.

The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the accounts were deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. Every account was deleted with UID and email absence confirmation. The run aged by real waiting and started from a committed checkout.

Recorded with the recorder files at commit `267b10f5a1edf70a2da1a7dff7260e9945f2bd05` while the repository was at `267b10f5a1edf70a2da1a7dff7260e9945f2bd05`. Re-evaluated at publication with the contract at commit `4c1097f4415bd20e30a09d15e787fc662f8f2a88`. The observation itself was not re-run.

This does not pin the exact pending lifetime or error precedence, does not separate pending-versus-session expiry, and does not generalize to tenants, blocking functions, SDK or Rules.

[Receipt](../../spec/compatibility/evidence/auth-pending-lifetime-boundary/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-lifetime-boundary/source-review.json). All earlier evidence and approvals remain unchanged.
