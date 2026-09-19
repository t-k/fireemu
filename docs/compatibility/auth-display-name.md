# Auth displayName observations

Status: candidate, not approved. These are redacted semantic observations, not retained raw responses or a signed attestation.

Display name REST updates using end-user tokens; no tenant; strict owned local artifact and recorded production configuration; auth-display-name corpus revision 1 only. Redacted semantic observations, not raw responses, independent JWT verification, expiry enforcement, SDK, MFA, Rules, credential changes or public npm compatibility.

| Case | Local | Production | Name state (local / production) |
|---|---|---|---|
| signup | Matched | Matched | — / — |
| initial-lookup | Matched | Matched | initial / initial |
| set-name | Matched | Matched | first / first |
| set-name-lookup | Matched | Matched | first / first |
| replace-name | Matched | Matched | second / second |
| replace-name-lookup | Matched | Matched | second / second |
| invalid-token-update | Matched | Matched | — / — |
| unchanged-state | Matched | Matched | — / — |
| delete-name | Matched | Matched | absent / absent |
| deleted-name-lookup | Matched | Matched | absent / absent |
| delete | Matched | Matched | — / — |
| deleted-account-absent | Matched | Matched | — / — |

Review subject (no approval granted): `f6e31fd28a7c05651df454843fe5c40c48b4e70552617b796f1398c702b0d2ec`.

The fixed synthetic names are Fireemu display first and Fireemu display second. initial identifies the private bootstrap marker; first/second identify corpus values. Absent, null and empty remain distinct; arbitrary names are never copied. Other/invalid-type remain visible mismatches. Classification is recorder testimony, not an independently reconstructable raw response.

Only displayName is changed after bootstrap. Before the first change, exact email/marker and independent UID lookups establish ownership; the UID is saved and reread from a private identity file. Subsequent ownership and cleanup require that UID and email, not the mutable name. Unknown-UID recovery still requires the original marker and persists the recovered UID before deletion. Reused email with another UID is refused. The original signup ID token is reused; profile-update token issuance and refresh are not checked. Malformed-token refusal is not an expired-token test. Refusal-state comparison includes localId, email, displayName, emailVerified, disabled, providerUserInfo and photoUrl; success identity checks cover localId, email, photoUrl, emailVerified and disabled, not provider synchronization or full state.

[Source and case mapping](../../spec/compatibility/evidence/auth-display-name/source-review.json) · [Redacted receipt](../../spec/compatibility/evidence/auth-display-name/receipt.json). The receipt binds fixed corpus, source review, probe/publication code, exact artifact/build/configuration and process exit. Published numeric expiry pertains only to account signup.

Admin APIs are limited to dedicated-account ownership and cleanup. Both exact UID and email selectors must confirm absence. Project/configuration preflight and owned-process shutdown are required. No human approval is inferred from either target matching. [Existing Auth basic approval](auth-basic-v2-approval.md) and [photoUrl approval](auth-profile-approval.md) and aggregation evidence are unchanged and do not cover this new subject.
