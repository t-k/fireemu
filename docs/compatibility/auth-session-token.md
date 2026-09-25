# Auth session token diagnostic observations

Status: candidate, not approved. Observed agreement is not a universal revocation guarantee or a feature-completion claim.

Diagnostic REST observation of frozen pre-change A/B ID and refresh tokens after session A changes the password, with changed-response token controls. No tenant; strict owned local artifact; recorded production authentication/password policy; auth-session-token revision 1. Target offsets 0/10/30 seconds, request-start deadline 45 seconds. No universal immediate-revocation oracle, SDK checkRevoked, Rules, elapsed expiry, same-second boundary, whole-session lineage, physical-device or public npm claim.

| Observation | Local | Production | Comparison | Actual interval ms (local / production) |
|---|---|---|---|---|
| signup | accepted | accepted | Same observed result | 9–12 / 10956–11517 |
| signin-a | accepted | accepted | Same observed result | 18–20 / 12223–12540 |
| signin-b | accepted | accepted | Same observed result | 2076–2083 / 14595–14891 |
| a-id-baseline | accepted | accepted | Same observed result | 2083–2089 / 14891–15196 |
| a-refresh-baseline-1 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2089–2096 / 15196–15756 |
| a-refresh-baseline-2 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2096–2102 / 15756–16308 |
| b-id-baseline | accepted | accepted | Same observed result | 2102–2104 / 16308–16610 |
| b-refresh-baseline-1 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2104–2110 / 16610–17153 |
| b-refresh-baseline-2 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2110–2118 / 17153–17726 |
| change-password | accepted | accepted | Same observed result | 5178–5185 / 20778–21181 |
| a-id@0 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 0–10 / 0–297 |
| a-refresh@0 | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (TOKEN_EXPIRED) | Different observations | 0–10 / 0–284 |
| b-id@0 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 1–10 / 6–281 |
| b-refresh@0 | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (TOKEN_EXPIRED) | Different observations | 1–12 / 6–274 |
| changed-id@0 | accepted | accepted | Same observed result | 1–13 / 7–301 |
| changed-refresh@0 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 2–17 / 9–636 |
| a-id@10000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 10000–10009 / 10010–10279 |
| a-refresh@10000 | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (TOKEN_EXPIRED) | Different observations | 10000–10009 / 10010–10301 |
| b-id@10000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 10000–10010 / 10010–10333 |
| b-refresh@10000 | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (TOKEN_EXPIRED) | Different observations | 10001–10010 / 10011–10301 |
| changed-id@10000 | accepted | accepted | Same observed result | 10001–10010 / 10011–10312 |
| changed-refresh@10000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 10001–10016 / 10011–10592 |
| a-id@30000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 30010–30017 / 30003–30284 |
| a-refresh@30000 | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (TOKEN_EXPIRED) | Different observations | 30010–30017 / 30003–30284 |
| b-id@30000 | auth-rejected (TOKEN_EXPIRED) | auth-rejected (TOKEN_EXPIRED) | Same observed result | 30010–30020 / 30003–30279 |
| b-refresh@30000 | auth-rejected (INVALID_REFRESH_TOKEN) | auth-rejected (TOKEN_EXPIRED) | Different observations | 30010–30020 / 30004–30281 |
| changed-id@30000 | accepted | accepted | Same observed result | 30011–30020 / 30004–30304 |
| changed-refresh@30000 | accepted / issued-ID lookup: accepted | accepted / issued-ID lookup: accepted | Same observed result | 30014–30023 / 30004–30582 |
| new-password-signin | accepted | accepted | Same observed result | 35208–35211 / 51764–52076 |
| new-password-lookup | accepted | accepted | Same observed result | 35211–35214 / 52076–52360 |
| delete | accepted | accepted | Same observed result | 35217–35220 / 52699–53124 |
| deleted-account-absent | accepted | accepted | Same observed result | 35225–35225 / 53772–53772 |

Review subject (no approval granted): `0539171a867622a1c8d1085f23151326676c0bcdbe95c7fcbc1e739203a20c7a`.

Baseline and final control intervals are measured from recorder start; @offset samples are measured from the completed password-change response. Each request records actual start/end and refresh-derived lookup intervals. Sample starts more than 2000ms late, completion beyond 45000ms, missing samples or failed fresh controls are inconclusive. The schedule never extends until rejection. A difference between timed observations is not automatically a runtime incompatibility or an exact revocation-latency measurement.

A and B are two REST signin credential sets for one dedicated account, separated before the change; they are not proven physical devices. Each original refresh token is used twice before mutation; the original ID and refresh bytes remain fixed afterward. Refresh rotation is recorded as a boolean, never substituted into the observed input. Successful refresh and successful use of its issued ID token are separate results. Exact-byte reuse is recorder testimony; token values and token digests are not public.

Session A performs accounts:update. Fresh changed-response ID and refresh credentials are sampled as controls, and replacement-password signin/lookup is checked after the window. Missing/control-invalid results do not establish conformance. No rejection within the window does not mean permanent validity. Frozen-token replay does not describe every token in a rotated session lineage. There is no no-password-change longitudinal control in this slice.

Timing claims iat/auth_time are decoded without signature verification and are published only as bounded numeric metadata. The recorder waits at least three monotonic seconds after baseline issuance, and requires the changed token's iat to exceed all pre-change issued iat values. validSince readback is advisory, not the oracle for REST acceptance. Same-second, SDK verifyIdToken/checkRevoked, Rules and actual elapsed-expiry tests are separate work.

HTTP requests have a five-second socket/processing budget; transport libraries do not provide a hard real-time cancellation guarantee. No new primary or refresh-derived lookup starts at/after the 45-second sampling deadline. In-flight workers drain before account cleanup, which has separate bounded request timeouts. Timing overruns cannot be re-labelled on-time success. Normal cleanup does not prove forced-termination/network-loss recovery.

[Source and case mapping](../../spec/compatibility/evidence/auth-session-token/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-session-token/receipt.json). The subject binds code, source review, corpus, artifact/configuration and owned-process exit. Raw tokens, passwords, account identifiers and responses are not published. No human approval is inferred. Earlier password-change and other approvals remain unchanged.
