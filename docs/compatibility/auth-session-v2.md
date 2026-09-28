# Auth session token revision 2 observations

Status: candidate, not approved. Observed agreement is not a universal revocation guarantee or a feature-completion claim.

Diagnostic REST observation of frozen pre-change A/B ID and refresh tokens after session A changes the password, with changed-response token controls. No tenant; strict owned local artifact; recorded production authentication/password policy; auth-session-v2 revision 2. Includes fixed malformed and unknown refresh-input controls. Target offsets 0/10/30 seconds, request-start deadline 45 seconds. No universal immediate-revocation oracle, SDK checkRevoked, Rules, elapsed expiry, same-second boundary, whole-session lineage, physical-device or public npm claim.

| Observation | Local | Production | Comparison | Actual interval ms (local / production) |
|---|---|---|---|---|
| signup | accepted | accepted | Same observed result | 9–12 / 10959–11463 |
| signin-a | accepted | accepted | Same observed result | 19–21 / 12140–12462 |
| signin-b | accepted | accepted | Same observed result | 2078–2082 / 14519–14805 |
| a-id-baseline | accepted | accepted | Same observed result | 2082–2085 / 14805–15087 |
| a-refresh-baseline-1 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2085–2090 / 15087–15686 |
| a-refresh-baseline-2 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2090–2096 / 15686–16238 |
| b-id-baseline | accepted | accepted | Same observed result | 2096–2099 / 16238–16519 |
| b-refresh-baseline-1 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2099–2104 / 16519–17073 |
| b-refresh-baseline-2 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2104–2112 / 17073–17638 |
| change-password | accepted | accepted | Same observed result | 5164–5171 / 20695–21092 |
| a-id@0 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 0–6 / 0–294 |
| a-refresh@0 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 0–6 / 0–262 |
| b-id@0 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 0–6 / 3–291 |
| b-refresh@0 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 0–8 / 3–274 |
| changed-id@0 | accepted | accepted | Same observed result | 0–7 / 4–291 |
| changed-refresh@0 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 1–10 / 4–556 |
| a-id@10000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 10010–10018 / 10012–10305 |
| a-refresh@10000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 10010–10017 / 10013–10278 |
| b-id@10000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 10010–10017 / 10013–10299 |
| b-refresh@10000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 10012–10018 / 10013–10283 |
| changed-id@10000 | accepted | accepted | Same observed result | 10012–10018 / 10013–10288 |
| changed-refresh@10000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 10012–10022 / 10014–10563 |
| a-id@30000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 30010–30017 / 30009–30281 |
| a-refresh@30000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 30010–30017 / 30009–30275 |
| b-id@30000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 30010–30020 / 30009–30283 |
| b-refresh@30000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 30010–30020 / 30009–30283 |
| changed-id@30000 | accepted | accepted | Same observed result | 30011–30021 / 30009–30294 |
| changed-refresh@30000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 30014–30023 / 30009–30561 |
| new-password-signin | accepted | accepted | Same observed result | 35194–35197 / 51653–51964 |
| new-password-lookup | accepted | accepted | Same observed result | 35197–35200 / 51964–52263 |
| malformed-refresh | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (INVALID_REFRESH_TOKEN) | Same observed result | 35200–35203 / 52263–52528 |
| unknown-refresh | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (INVALID_REFRESH_TOKEN) | Same observed result | 35203–35205 / 52528–52795 |
| delete | accepted | accepted | Same observed result | 35208–35211 / 53117–53561 |
| deleted-account-absent | accepted | accepted | Same observed result | 35216–35216 / 54206–54206 |

Review subject (no approval granted): `2650710c03f4ea3fce3e066ef14be16be801b63af14916666b7d7a5bfb24e4f1`.

Baseline and final control intervals are measured from recorder start; @offset samples are measured from the completed password-change response. Each request records actual start/end and refresh-derived lookup intervals. Sample starts more than 2000ms late, completion beyond 45000ms, missing samples or failed fresh controls are inconclusive. The schedule never extends until rejection. A difference between timed observations is not automatically a runtime incompatibility or an exact revocation-latency measurement.

A and B are two REST signin credential sets for one dedicated account, separated before the change; they are not proven physical devices. Each original refresh token is used twice before mutation; the original ID and refresh bytes remain fixed afterward. Refresh rotation is recorded as a boolean, never substituted into the observed input. Successful refresh and successful use of its issued ID token are separate results. Exact-byte reuse is recorder testimony; token values and token digests are not public.

Session A performs accounts:update. Fresh changed-response ID and refresh credentials are sampled as controls, and replacement-password signin/lookup is checked after the window. Missing/control-invalid results do not establish conformance. No rejection within the window does not mean permanent validity. Frozen-token replay does not describe every token in a rotated session lineage. There is no no-password-change longitudinal control in this slice.

Timing claims iat/auth_time are decoded without signature verification and are published only as bounded numeric metadata. The recorder waits at least three monotonic seconds after baseline issuance, and requires the changed token's iat to exceed all pre-change issued iat values. validSince readback is advisory, not the oracle for REST acceptance. Same-second, SDK verifyIdToken/checkRevoked, Rules and actual elapsed-expiry tests are separate work.

HTTP requests have a five-second socket/processing budget; transport libraries do not provide a hard real-time cancellation guarantee. No new primary or refresh-derived lookup starts at/after the 45-second sampling deadline. In-flight workers drain before account cleanup, which has separate bounded request timeouts. Timing overruns cannot be re-labelled on-time success. Normal cleanup does not prove forced-termination/network-loss recovery.

[Source and case mapping](../../spec/compatibility/evidence/auth-session-v2/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-v2/receipt.json). The subject binds code, source review, corpus, artifact/configuration and owned-process exit. Raw tokens, passwords, account identifiers and responses are not published. No human approval is inferred. Revision 1 and all earlier approvals remain unchanged; historical integrity is checked with tools/compat-history/history.py --check at its pinned source anchor. This candidate uses a new artifact and subject.
