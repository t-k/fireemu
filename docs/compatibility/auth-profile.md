# Auth photo URL observations

Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.

Photo URL REST updates using end-user tokens; no tenant; strict owned local artifact and recorded production configuration; auth-photo-url corpus revision 1 only. Redacted semantic observations, not raw responses, independent JWT verification, expiry enforcement, SDK, MFA, Rules, credential changes or public npm compatibility.

| Case | Local | Production | Photo state (local / production) |
|---|---|---|---|
| signup | Matched | Matched | — / — |
| initial-lookup | Matched | Matched | absent / absent |
| set-photo | Matched | Matched | first / first |
| set-photo-lookup | Matched | Matched | first / first |
| replace-photo | Matched | Matched | second / second |
| replace-photo-lookup | Matched | Matched | second / second |
| invalid-token-update | Matched | Matched | — / — |
| unchanged-state | Matched | Matched | — / — |
| delete-photo | Matched | Matched | absent / absent |
| deleted-photo-lookup | Matched | Matched | absent / absent |
| delete | Matched | Matched | — / — |
| deleted-account-absent | Matched | Matched | — / — |

Review subject (no approval granted): `23913299c5d414abbdffe0692711f77ead500b639318a09a60a5802bd1f199d2`.

The fixed synthetic URLs use example.invalid. first/second identify corpus values; absent, null and empty remain distinct. Arbitrary URL values are never copied; other/invalid-type remain visible mismatches. No image is fetched or uploaded by the recorder. The response classification is recorder testimony, not an independently reconstructable raw response.

Only photoUrl is changed; displayName remains the ownership marker. The original signup ID token is reused. Profile-update token issuance and refresh behavior are not checked. Refusal uses a deliberately malformed token, not an expired token. State preservation compares localId, email, displayName, emailVerified, disabled, providerUserInfo and photoUrl; it is not a full-state guarantee. Successful update lookups separately compare selected identity fields, without claiming provider synchronization.

[Source and case mapping](../../spec/compatibility/evidence/auth-profile/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-profile/receipt.json). The receipt binds fixed corpus, source review, probe/publication code, exact artifact/build/configuration and process exit. Published numeric expiry pertains only to account signup.

Admin APIs are limited to dedicated-account ownership and cleanup. Both exact UID and email selectors must confirm absence. Project/configuration preflight and owned-process shutdown are required. No human approval is inferred from either target matching. [Existing Auth approval](auth-basic-v2-approval.md) and aggregation evidence are unchanged and do not cover this new subject.
