# Auth session continuity without password change

Status: candidate, not approved. This independent control does not inherit the password-change observation approval.

No-password-change REST continuity control for fixed A/B ID and refresh tokens plus reference-exchange credentials; no tenant, local strict owned artifact, recorded production authentication/password-policy settings; auth-session-continuity revision 1, 34 observations. Target offsets 0/10/30 seconds after reference exchange and its derived lookup, 45-second request-start deadline. All scheduled primary and derived lookups must succeed for continuity. No credential mutation, one-hour expiry, permanent validity, whole-session lineage, SDK or Rules claim.

| Observation | Local | Production | Comparison | Actual interval ms (local / production) |
|---|---|---|---|---|
| signup | accepted | accepted | Same observed result | 10–14 / 10223–10729 |
| signin-a | accepted | accepted | Same observed result | 20–23 / 11376–11677 |
| signin-b | accepted | accepted | Same observed result | 2083–2086 / 13728–14032 |
| a-id-baseline | accepted | accepted | Same observed result | 2086–2089 / 14032–14317 |
| a-refresh-baseline-1 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2089–2095 / 14317–14900 |
| a-refresh-baseline-2 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2095–2100 / 14900–15447 |
| b-id-baseline | accepted | accepted | Same observed result | 2100–2103 / 15447–15723 |
| b-refresh-baseline-1 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2103–2109 / 15723–16268 |
| b-refresh-baseline-2 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2109–2117 / 16268–16850 |
| reference-refresh | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 5175–5181 / 19904–20483 |
| a-id@0 | accepted | accepted | Same observed result | 0–7 / 0–275 |
| a-refresh@0 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 0–11 / 6–537 |
| b-id@0 | accepted | accepted | Same observed result | 0–6 / 6–296 |
| b-refresh@0 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 0–11 / 6–571 |
| reference-id@0 | accepted | accepted | Same observed result | 0–8 / 7–323 |
| reference-refresh@0 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 1–11 / 10–568 |
| a-id@10000 | accepted | accepted | Same observed result | 10004–10010 / 10008–10296 |
| a-refresh@10000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 10004–10014 / 10009–10570 |
| b-id@10000 | accepted | accepted | Same observed result | 10005–10010 / 10009–10309 |
| b-refresh@10000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 10005–10014 / 10014–10573 |
| reference-id@10000 | accepted | accepted | Same observed result | 10005–10010 / 10014–10311 |
| reference-refresh@10000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 10005–10014 / 10014–10616 |
| a-id@30000 | accepted | accepted | Same observed result | 30002–30017 / 30000–30272 |
| a-refresh@30000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 30002–30023 / 30000–30591 |
| b-id@30000 | accepted | accepted | Same observed result | 30002–30017 / 30001–30304 |
| b-refresh@30000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 30002–30022 / 30001–30576 |
| reference-id@30000 | accepted | accepted | Same observed result | 30002–30017 / 30001–30293 |
| reference-refresh@30000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 30003–30023 / 30002–30573 |
| final-signin | accepted | accepted | Same observed result | 35204–35207 / 51075–51373 |
| final-lookup | accepted | accepted | Same observed result | 35207–35210 / 51373–51659 |
| malformed-refresh | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (INVALID_REFRESH_TOKEN) | Same observed result | 35210–35213 / 51659–51925 |
| unknown-refresh | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (INVALID_REFRESH_TOKEN) | Same observed result | 35213–35216 / 51925–52196 |
| delete | accepted | accepted | Same observed result | 35219–35222 / 52540–52959 |
| deleted-account-absent | accepted | accepted | Same observed result | 35227–35227 / 53613–53613 |

Review subject (no approval granted): `8d8214f936b5061bf584e164f55a4a41c8a0a346354b0cb955c04973e29ee0b2`.

One dedicated account supplies two separated signin credential sets A/B. Their original ID and refresh bytes are frozen, and each original refresh token works twice before observation. After at least three seconds, reference-refresh exchanges A's original refresh token and performs lookup with the issued ID token. Sampling starts after this complete reference operation. Reference refresh bytes may equal A's original refresh token: this is not a third independent session, physical device or newly rotated lineage.

The recorder does not call accounts:update, resetPassword or explicit revocation. Final signin uses the original password. Account setup/deletion and signin/exchange bookkeeping still occur: no password change does not mean an entirely read-only server workload. Fixed invalid-refresh inputs are sent after the window. Admin APIs identify and clean up the dedicated account; they do not mutate its credentials.

All six scheduled lanes require accepted primary responses and successful refresh-derived ID lookups to establish continuity. Matching token rejections, failed controls, transport failures and missing samples are inconclusive, not successful continuity. Actual starts over 2000ms late or completion beyond 45000ms are late. The schedule never extends until success. Baseline/final intervals use recorder start; @offset intervals use completion of the reference exchange and its lookup. Each primary and dependent interval remains separately recorded in the receipt.

This bounded run complements, but does not retroactively extend, the separately approved password-change experiment. The runs use different dedicated accounts and were not simultaneous randomized causal trials. No permanent refresh validity, one-hour elapsed-expiry behavior, same-second boundary, whole rotated-session lineage, SDK checkRevoked, Rules, MFA or public npm artifact guarantee follows.

JWT iat/auth_time metadata is decoded without signature verification. The later reference-issued ID token must have iat greater than earlier recorded issuance, but its auth_time may remain from the original signin. Token byte reuse and identity comparisons are recorder testimony; raw tokens, token digests, passwords, UID/email and raw responses are not public.

Requests use a five-second socket/processing budget, not hard real-time cancellation. No new primary or derived lookup starts at/after the 45-second sampling deadline; workers drain before separate account cleanup. Normal UID/email absence and owned-process exit/listener closure do not prove network-loss or forced-termination recovery.

[Source and case mapping](../../spec/compatibility/evidence/auth-session-continuity/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-continuity/receipt.json). Source snapshots retain their original acquisition dates. Earlier observations and approvals remain unchanged, including the [approved password-change slice](auth-session-v2-approval.md).
