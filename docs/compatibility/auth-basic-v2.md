# Auth basic revision 2

Status: candidate, not approved. This is an explicitly redacted semantic receipt, not retained raw Auth responses or a signed attestation.

Email/password REST; default project; strict local artifact and recorded production configuration; corpus revision 2; twelve cases only; redacted semantic observations, not raw responses or independent JWT signature/expiry enforcement proof. No SDK, Rules, MFA, OOB, tenant, public npm or complete Auth claim.

The twelve-case corpus adds signup-token lookup, signup-token refresh and lookup using that refreshed token. Numeric expiry is retained and checked separately for positive-integer shape and the explicit 3600-second expectation. Actual expired-token refusal is not tested.

| Case | Local | Production | Expiry seconds (local / production) |
|---|---|---|---|
| signup | Matched | Matched | 3600 / 3600 |
| signup-token-lookup | Matched | Matched | — / — |
| signup-token-refresh | Matched | Matched | 3600 / 3600 |
| signup-refreshed-lookup | Matched | Matched | — / — |
| signin | Matched | Matched | 3600 / 3600 |
| lookup | Matched | Matched | — / — |
| wrong-password | Matched | Matched | — / — |
| unchanged-state | Matched | Matched | — / — |
| refresh | Matched | Matched | 3600 / 3600 |
| refreshed-lookup | Matched | Matched | — / — |
| delete | Matched | Matched | — / — |
| deleted-account-absent | Matched | Matched | — / — |

Review subject (no approval granted): `0eb3689e1eb636f4166d3f296bba2fea2cf2ac70bf6ab6901d1077575a2a60cb`.

[Public redacted receipt](../../spec/compatibility/evidence/auth-basic-v2/receipt.json) includes exact artifact/configuration/build inputs, process identity/exit checks and production configuration projection. Offline validation rechecks those relationships, expiry predicates and case verdict consistency. Token presence, identity relationships and service acceptance remain recorder observations; no reusable token values, passwords, raw account records or recovery journals are published. This is not independent cryptographic verification of the live service.

[Source and case mapping](../../spec/compatibility/evidence/auth-basic-v2/source-review.json) extends the [selected-section review](auth-basic-source-review.md). [Original nine-case observations](auth-basic-evidence.md) and aggregation approvals remain unchanged. Human approval must name this subject and its limited redacted-observation scope; it cannot be transferred after an input or case change.
