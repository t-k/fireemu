# Firebase App Check support specification

- Status: proposed (review decisions of 2026-08-30 applied; see section 25)
- Specification date: 2026-08-30
- Target: `fireemu`
- Initial delivery: baseline App Check for Auth, Cloud Firestore, Cloud Storage for Firebase, and callable Cloud Functions
- Enforcement precision: `boundary-conformance` until the product-specific conformance fixtures in this document pass

## 1. Decision summary

`fireemu` does not currently model Firebase App Check. It has no App Check configuration, app registry, debug-token exchange, token issuer, verifier, request admission decision, metrics, capability entry, or tests. Some request paths forward `X-Firebase-AppCheck` accidentally, while other paths discard it. Accidental forwarding is not support.

The selected design adds a reproducible-under-test local App Check issuer and one transport-neutral verification and enforcement core. Normal daemon instances use cryptographically independent signing material; an explicitly injected test seed makes focused tests deterministic. Client test code exchanges a registered local debug secret for a session-scoped RS256 JWT. Firebase product adapters read `X-Firebase-AppCheck`, resolve the target project, ask the common core for one decision, and apply a product-specific enforcement policy before Security Rules or state mutation. Firebase Authentication and Security Rules remain independent layers; a request may have any combination of valid, missing, or invalid Auth and App Check credentials.

The initial delivery includes baseline protection. Limited-use token consumption and replay protection remain a separately declared capability because the current Functions runner delegates callable context construction to the installed `firebase-functions` package and cannot yet communicate `alreadyConsumed` without a trusted runner protocol extension.

## 2. Evidence for the current gap

The following repository evidence establishes the baseline as of the specification date:

- `RuntimeConfig` and the closed canonical JSON Schema contain no App Check state or policy.
- Firestore gRPC reads only `authorization` metadata. Firestore REST and WebChannel copy only `Authorization` into their internal request models.
- The Auth/control HTTP listener normalizes only authorization, origin, content type, and host.
- The Storage HTTP adapter uses a fixed header allowlist that omits `X-Firebase-AppCheck`.
- The Functions proxy forwards arbitrary headers, but neither the daemon nor the runner validates App Check tokens.
- The canonical capability manifest and every test layer contain no App Check capability or scenario.

This is an unsupported feature, not a documentation omission.

## 3. Goals

The implementation shall:

1. Exercise the same client integration point used in production: `X-Firebase-AppCheck` on Firebase service requests.
2. Work offline after dependencies are installed. Token issuance and verification must not call Google or an attestation provider.
3. Reject malformed, forged, expired, wrong-project, and unknown-app tokens deterministically.
4. Support production-shaped RS256 JWT claims, a local JWKS endpoint, and virtual-clock expiry tests.
5. Model `OFF`, `UNENFORCED`, and `ENFORCED` baseline modes separately for Auth, Firestore, and Storage.
6. Preserve per-function `enforceAppCheck` behavior for callable Functions and populate `request.app` or `context.app` for valid tokens.
7. Keep privileged Admin, control, UI, token-exchange, and JWKS routes out of end-user App Check enforcement through explicit bypass rules.
8. Apply App Check before Security Rules evaluation, function invocation, upload mutation, Auth mutation, or Firestore mutation.
9. Isolate app registrations, token validity, counters, and future replay state by project and session epoch.
10. Expose structured, secret-free observations suitable for tests and the Emulator UI.
11. Fail closed when a requested App Check capability is unsupported.

## 4. Non-goals

The initial delivery shall not:

- emulate Play Integrity, App Attest, DeviceCheck, reCAPTCHA, or any other production attestation provider;
- attest a real device or claim that a local token proves device integrity;
- proxy token exchange or verification to a production Firebase project;
- enable App Check for products that `fireemu` does not emulate;
- add App Check data to Firestore or Storage Security Rules; App Check is a service admission layer, not `request.auth`;
- automatically enforce App Check on ordinary `onRequest` functions;
- make the unmodified Firebase Admin SDK use the local JWKS endpoint when that SDK hard-codes Google's JWKS URL;
- support limited-use token consumption or replay protection in the initial milestone;
- treat the daemon as a production security boundary. It remains a loopback-only test runtime.

## 5. Considered approaches

### 5.1 Selected: instance-isolated local issuer and common enforcement core

The daemon registers Firebase app IDs and debug-token digests, exchanges a matching debug secret for a locally signed RS256 JWT, and verifies that JWT at every supported ingress. This preserves meaningful signature, issuer, audience, subject, expiry, app registration, and project-binding tests without network access.

Trade-off: clients must use a local custom App Check provider or a small test helper because official App Check SDKs do not expose a general emulator-host switch. The token is production-shaped but locally signed and is not valid against Google services.

### 5.2 Rejected: production passthrough

This approach would accept tokens from Google's App Check service and fetch the production JWKS. It offers production signatures but makes tests depend on credentials, network access, provider quotas, external clock behavior, and mutable project configuration. It also risks sending local test traffic and secrets to a real project.

### 5.3 Rejected: opaque or unsigned local tokens

This approach would recognize a magic string or decode an unsigned JWT. It is simple, but it cannot detect signature bypasses, wrong keys, altered claims, or unknown key IDs. It would turn `enforceAppCheck` into a header-presence test and conflict with the repository's fail-closed and published-precision decisions.

## 6. Capability model

The capability manifest shall add the following entries. An entry must remain `unsupported` until its acceptance criteria are executable.

| Capability ID | Initial status | Precision target | Contract |
|---|---|---|---|
| `APPCHECK-CORE-1` | planned | exact for local semantics | Project-scoped app registry, instance-isolated RS256 token issuance and verification, virtual-clock expiry, and reproducible identifiers under an injected test seed |
| `APPCHECK-DEBUG-EXCHANGE-1` | planned | boundary-conformance | `v1` and `v1beta` debug-token exchange plus privileged local debug-token management |
| `APPCHECK-JWKS-1` | planned | exact for local semantics | Public local App Check JWKS containing no private material |
| `APPCHECK-ENFORCE-1` | planned | boundary-conformance | `OFF`, `UNENFORCED`, and `ENFORCED` decisions for Auth, Firestore, and Storage |
| `APPCHECK-FUNCTIONS-1` | planned | boundary-conformance | Callable `enforceAppCheck`, valid callable app context, and invalid-token removal before unsafe runner decoding |
| `APPCHECK-OBSERVE-1` | planned | exact for local semantics | Structured decisions and counters with token and debug-secret redaction |
| `APPCHECK-SDK-WEB-1` | planned | boundary-conformance | Real Firebase Web SDK smoke using `CustomProvider` against local exchange |
| `APPCHECK-REPLAY-1` | unsupported | unsupported | Limited-use issuance, atomic consumption, concurrent replay observation, and callable `alreadyConsumed` propagation |
| `APPCHECK-PROVIDER-ATTESTATION-0` | unsupported | not-applicable | Production attestation providers are outside local emulation |

`APPCHECK-CORE-1`, `APPCHECK-ENFORCE-1`, `APPCHECK-FUNCTIONS-1`, and `APPCHECK-SDK-WEB-1` are required before the project may advertise App Check support without qualification.

## 7. Domain model and boundaries

### 7.1 Core crate

A new `fireemu-core-app-check` crate shall contain only deterministic domain logic and shall follow ADR-001. Network I/O, HTTP, process environment, RSA key ownership, and every cryptographic primitive remain outside the core: the core defines small traits for the SHA-256 digest of a debug secret and for constant-time digest comparison (and for the RS256 signer, matching the existing Auth pattern), and the runtime shell implements them with standard crates (`sha2`, `subtle`, `rsa`). The core never contains a hand-written hash or comparison routine; in particular the Rules `hashing` namespace implementation in `fireemu-core-rules` is not shared, since it declares itself unsuitable for runtime collision resistance.

The core owns these concepts:

- `AppCheckRegistry`: project-scoped registered apps, project number binding, static and dynamic debug-token digests, and the current session epoch;
- `RegisteredApp`: `project_id`, `project_number`, `app_id`, enabled state, and debug-token digest metadata;
- `AppCheckClaims`: issuer, subject, audiences, issued-at time, expiry, instance-authenticated token ID, local epoch, and token class;
- `AppIdentity`: verified `app_id`, project ID, project number, issued-at time, expiry, token ID, and token class;
- `AppCheckCredentialState`: `Bypass`, `Missing`, `Valid(AppIdentity)`, or `Invalid(AppCheckFailure)`;
- `AppCheckFailure`: stable internal reasons including `Malformed`, `UnsupportedAlgorithm`, `UnknownKeyId`, `BadSignature`, `NotYetValid`, `Expired`, `WrongIssuer`, `WrongAudience`, `UnknownApp`, `AppDisabled`, `WrongProject`, and `WrongEpoch`;
- `BaselineMode`: `Off`, `Unenforced`, or `Enforced`;
- `AdmissionDecision`: credential state, selected mode, allow or deny outcome, public reason code, and a redacted observation.

App Check identity must not be added to the existing Auth `Principal`. The credentials are orthogonal, have different issuers, have different bypass rules, and are evaluated at different layers.

### 7.2 Signing boundary

The runtime shell owns a dedicated App Check RS256 key pair, generated once per daemon instance (never per project). It must not reuse the Firebase Auth signing key. On a normal start, the key is generated from the operating system CSPRNG and is never exported (the daemon already draws its control token and runner secret from the CSPRNG, so it is not a seed-only reproducible process). Tests inject a seed through constructor injection of an `AppCheckKeySource` / signer factory, never through a `RuntimeConfig` field: configuration values and test dependencies stay separate, and the seam is unavailable in canonical configuration and production-like CLI startup. When both `auth.idTokenSigning = "session-rsa"` and `appCheck.enabled` are set, two keys are generated; they may be generated concurrently (`spawn_blocking`). Derivation from an injected seed uses an App Check-specific domain separator. Two normal daemon instances with identical project configuration must still reject each other's tokens.

The signer implements a small core trait with `alg`, `kid`, `sign`, `verify`, and `public_jwk_json`, matching the existing Auth key-isolation pattern. Its `kid` begins with `fireemu-app-check-` and is derived from the public key. Each project epoch is an unpredictable 128-bit value generated at project creation and every invalidating lifecycle transition. Key or epoch rotation and publication occur under the admission barrier: new requests see either the entire old state or the entire new state. Private keys and instance secrets use zeroizing, redacting non-`Debug` wrappers. Epochs use a redacting non-`Debug` wrapper. The raw epoch necessarily appears as the signed `fireemu_epoch` claim and in decoded callable claims returned to the token holder; it is an opaque binding value, not an independent credential. It must not additionally appear in configuration output, traces, snapshots, logs, UI responses, panic messages, or debug formatting.

### 7.3 Canonical credential-header handling

Every automatically classified ingress uses the same case-insensitive `X-Firebase-AppCheck` extraction contract. Zero values classify as `Missing`. Exactly one nonempty ASCII value of at most 16 KiB is eligible for verification. Multiple field instances, comma-folded values, invalid text, empty values, or larger values classify as `Malformed`; adapters must not select the first or last value. The same contract applies to HTTP/1, HTTP/2, gRPC metadata, WebChannel, Storage, and callable Functions.

Before forwarding a callable request, the Functions proxy removes every case-insensitive caller-supplied App Check header. It reinserts exactly one byte-for-byte token only after daemon verification succeeds. Invalid and missing values are forwarded without an App Check header. This sanitation occurs before any runner-side unsafe decoding.

Ordinary `onRequest` functions are the deliberate exception because application code owns custom-backend verification. The proxy performs HTTP framing validation but otherwise forwards the received App Check field list without classifying or selecting a value; the HTTP stack may normalize field names but must not merge duplicates into a value that the daemon labels valid. Duplicate and folded values remain untrusted application input, and no automatic app identity is constructed.

### 7.4 Request flow

Every protected request follows this order:

```text
transport origin and framing checks
    -> route and target-project resolution
    -> explicit privileged-bypass classification
    -> App Check credential classification
    -> baseline enforcement decision
    -> Firebase Auth classification
    -> request validation and Security Rules
    -> state transition or function invocation
    -> redacted observation
```

No adapter may reimplement JWT semantics. Adapters translate transport headers and wire errors only.

## 8. Canonical configuration

The canonical JSON Schema shall add this optional top-level section:

```json
{
  "appCheck": {
    "enabled": true,
    "tokenSigning": "instance-rsa",
    "tokenTtlSeconds": 3600,
    "apps": [
      {
        "projectId": "demo-app",
        "projectNumber": "1234567890",
        "appId": "1:1234567890:web:local-test-app",
        "enabled": true,
        "debugTokenSha256": [
          "db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98"
        ]
      }
    ],
    "services": {
      "auth": "off",
      "firestore": "unenforced",
      "storage": "unenforced"
    }
  }
}
```

The schema and Rust loader shall enforce the same rules:

- `enabled` defaults to `false` so existing projects preserve current behavior.
- `tokenSigning` accepts only `instance-rsa` in the first implementation (the name differs from Auth's `session-rsa` on purpose: the App Check key belongs to the daemon instance, not to the reproducible session seed). Unsigned modes are rejected.
- `tokenTtlSeconds` defaults to `3600` and must be between 1,800 seconds and 604,800 seconds inclusive, matching the documented production session-token TTL range.
- `apps` defaults to an empty list. Duplicate `(projectId, appId)` entries are rejected.
- Across all app entries, one project ID maps to exactly one project number, one project number maps to exactly one project ID, and one app ID belongs to exactly one such project. Conflicts in either mapping direction and cross-project app ID reuse are rejected.
- `enabled` on an app defaults to `true`. Disabling an app rejects new exchanges and invalidates its previously issued tokens at their next verification because enabled state is checked on every request.
- `projectNumber` contains decimal ASCII digits and is compared as a string. Leading zeros are rejected.
- When an app ID has the standard `1:{projectNumber}:{platform}:{opaque}` form, its embedded project number must equal `projectNumber`.
- `debugTokenSha256` values are lowercase 64-character hexadecimal SHA-256 digests of the lowercase hyphenated canonical UUIDv4 bytes. Raw debug secrets are forbidden in canonical configuration.
- `services` and each omitted service member default to `off`. Keys accept `off`, `unenforced`, or `enforced`; unknown services and values are errors.
- A non-`off` service mode is invalid when `enabled` is false.
- `firebase.json` has no App Check mapping because production enforcement is console/API configuration, not Local Emulator Suite file configuration.
- Unknown keys fail closed at every level.

At most 1,024 apps may be configured per daemon and at most 128 debug-token digests may be registered per app. App IDs are limited to 256 UTF-8 bytes, display names to 128 UTF-8 bytes, JWT/header values to 16 KiB, and exchange JSON bodies to 16 KiB with no trailing JSON value. Observations aggregate unknown and invalid identities into bounded buckets; they never create a metric label from unverified input.

`--only appcheck` shall be accepted as a logical service selection even though App Check shares the Auth/control HTTP listener. `fireemu exec` shall export `FIREEMU_APP_CHECK_EMULATOR_HOST=host:port` and `FIREEMU_APP_CHECK_JWKS_URL=http://host:port/v1/jwks` when App Check is selected. No raw debug secret is generated or exported implicitly.

The activation contract is:

| Configuration and service selection | Exchange/JWKS | Product baselines | Callable trusted protocol |
|---|---|---|---|
| `appCheck.enabled` omitted or `false` | unavailable | all `off` | inactive; current Functions behavior is unchanged |
| enabled, neither `appcheck` nor `functions` selected by `--only` | unavailable | all `off` | not applicable |
| enabled and `appcheck` selected, Functions not selected | available | selected non-Functions services apply configured modes | not applicable |
| enabled and `functions` selected | available because Functions selects its App Check dependency | selected non-Functions services apply configured modes only when explicitly selected | active for callable requests, including callables without enforcement so valid app context is available |

When `--only` is absent, an enabled App Check configuration selects the logical `appcheck` service. With `--only`, selecting `functions` implicitly selects its App Check exchange/verifier dependency when App Check is enabled; other products require both their own name and `appcheck`. A selected service whose configured mode is omitted remains `off`. `consumeAppCheckToken: true` always fails discovery while replay support is unavailable.

## 9. App registration and debug secrets

App registrations come only from canonical configuration in the initial delivery. Dynamic debug-token registrations use privileged control routes and are scoped to a configured app and project:

- `POST /emulator/v1/projects/{project}/apps/{appId}/debugTokens`
- `GET /emulator/v1/projects/{project}/apps/{appId}/debugTokens`
- `DELETE /emulator/v1/projects/{project}/apps/{appId}/debugTokens/{tokenId}`

Creation accepts a display name and either a caller-supplied UUIDv4 debug secret or a request to generate one. UUID input is parsed and converted to lowercase hyphenated canonical form before hashing, so hexadecimal case does not change the credential. The response may return the raw secret exactly once and sets `Cache-Control: no-store`. The registry stores only its SHA-256 digest. List responses contain token ID, display name, creation logical time, and digest prefix, never the raw secret or full digest. Deletion takes effect for subsequent exchanges but does not revoke already issued session tokens.

A request for an unconfigured app fails with the same public error shape used for an unknown project. App creation and deletion APIs are outside the initial delivery; this avoids an undocumented second source of truth for project number and app ID binding.

Every management request requires a valid control token and a loopback-bound listener, regardless of HTTP method, `Origin` presence, client type, or whether the request would otherwise be read-only. `Origin`, `Host`, an API key, and loopback source alone never grant access. The response to every creation, list, and deletion request sets `Cache-Control: no-store`; CORS permits only explicitly configured loopback development origins and never uses a credentialed wildcard. The routes are not App Check protected because they configure App Check itself. Tests cover absent and foreign origins, missing and wrong control tokens, and every supported method.

## 10. Exchange and JWKS protocol

### 10.1 Debug-token exchange

The shared HTTP listener shall implement both production-shaped routes:

- `POST /v1/projects/{project}/apps/{appId}:exchangeDebugToken`
- `POST /v1beta/projects/{project}/apps/{appId}:exchangeDebugToken`

`project` may be the configured project ID or project number. The JSON request is:

```json
{
  "debugToken": "00000000-0000-4000-8000-000000000000",
  "limitedUse": false
}
```

The API key query parameter is accepted and ignored. The request succeeds only when the target app exists, is enabled, belongs to the selected project, and the constant-time SHA-256 digest comparison matches a registered debug token. Exchange canonicalizes UUIDv4 text exactly as registration does before hashing. It scans the fixed-capacity digest set without early exit and performs equivalent dummy work for an unknown app. This limits timing differences but does not claim resistance to a local process-level side channel. A successful response sets `Cache-Control: no-store` and is:

```json
{
  "token": "<signed JWT>",
  "ttl": "3600s"
}
```

`limitedUse: true` returns `501 UNIMPLEMENTED` with stable code `APP_CHECK_REPLAY_UNSUPPORTED` until `APPCHECK-REPLAY-1` is implemented. It must never silently return a reusable session token.

Malformed input returns `400 INVALID_ARGUMENT`. Unknown apps, projects, and debug secrets return the same `403 PERMISSION_DENIED` public message, `App attestation failed.`, so the response body is not an app or secret enumeration oracle. Detailed reason codes are available only in control-token-authenticated structured observations.

### 10.2 JWKS

The listener shall expose the public key at:

- `GET /v1/jwks`
- `GET /v1beta/jwks`

The response is an RFC 7517 JWK Set with `Cache-Control: no-store`. It contains only the dedicated App Check public key. The endpoints are public on loopback and are not App Check protected. Disabling cache is an intentional local divergence: normal daemon restart creates a new key at the same loopback URL, and clients must not retain the previous instance's JWKS.

### 10.3 Client integration

The Web SDK acceptance path uses `initializeAppCheck` with `CustomProvider`. The provider sends the configured debug secret and `limitedUse: false` to the local exchange endpoint and returns the response token with an expiration time calculated from `ttl`. Firestore, Storage, Auth, and Functions SDKs then attach the returned token through their normal App Check provider integration.

The project shall provide a minimal test helper or documented provider example. It must not patch SDK internals, replace Firebase service clients, disable signature checks in the daemon, or send a production debug token to the local runtime.

## 11. Token contract

The local session token is an RS256 JWT with `typ: JWT`, the local App Check `kid`, and these claims:

| Claim | Required value |
|---|---|
| `iss` | `https://firebaseappcheck.googleapis.com/{projectNumber}` |
| `sub` | registered Firebase app ID |
| `aud` | array containing `projects/{projectNumber}` and `projects/{projectId}` |
| `iat` | virtual-clock Unix seconds at exchange |
| `exp` | `iat + tokenTtlSeconds` |
| `jti` | unique token ID within the project epoch (epoch plus an atomic counter) |
| `fireemu_epoch` | current project session epoch; local-only private claim |

The verifier shall require:

1. exactly three compact-JWT segments and valid unpadded base64url;
2. `alg: RS256`, `typ: JWT`, and a known local App Check `kid`;
3. a valid signature before trusting any claim;
4. integer `iat` and `exp`, with `iat <= now < exp` and `exp > iat`;
5. an issuer exactly equal to `https://firebaseappcheck.googleapis.com/{projectNumber}`;
6. both project audiences;
7. a non-empty `sub` naming an enabled app registered in the target project;
8. an `fireemu_epoch` equal to the current project session epoch;
9. a non-empty `jti`.

The issuer creates `jti` from the project epoch and an atomic per-epoch counter. No separate HMAC is needed: the whole JWT is RS256-signed, so `jti` is authenticated by the signature; uniqueness comes from the epoch plus the counter. Concurrent exchanges cannot reuse a token ID. Reset and restore rotate the epoch before resetting the counter, so counter reuse cannot recreate a valid token. Focused tests may reproduce IDs only by injecting the same test seed and operation order.

Token verification uses the virtual clock. It does not consult Auth users, API keys, request origins, or Security Rules. The token's `app_id` convenience property is derived from `sub` when exposing callable context; it need not be a duplicate JWT claim.

The private `fireemu_epoch` claim intentionally makes local tokens non-portable across reset, restore, project deletion, or daemon instances. This is a published local-runtime divergence that prevents a pre-reset token or cleared replay ledger from authorizing a post-reset request.

## 12. Enforcement semantics

### 12.1 Baseline modes

| Mode | Token work | Invalid or missing request | Observation |
|---|---|---|---|
| `off` | No parsing or verification | Allowed | No App Check traffic metric |
| `unenforced` | Classify and verify | Allowed; no app identity is exposed for missing or invalid tokens | Recorded |
| `enforced` | Classify and verify | Valid or explicit bypass is allowed; missing or invalid is denied | Recorded |

A malformed or invalid token is never converted into an anonymous valid app. Auth and Security Rules still run in `unenforced` mode, but they receive no App Check identity.

### 12.2 Privileged bypass matrix

| Surface | Bypass baseline enforcement | Rationale |
|---|---|---|
| Control API and Emulator UI API | yes | Privileged local administration with separate control-token guard |
| App Check exchange and JWKS | yes | Bootstrap and public-key discovery |
| Firestore verified owner/Admin path | yes | Production App Check enforcement may exempt privileged service-account traffic; existing emulator owner contract remains explicit |
| Storage authenticated JSON API privileged/Admin dialect | yes | Existing privileged server surface |
| Identity Toolkit Admin SDK routes with a verified owner principal | yes | Server administration is not an end-user app request |
| Storage Firebase download URL with a verified download token bound to the requested object | yes | The download token is an explicit bearer capability intended for URL access outside an initialized Firebase app |
| Ordinary `onRequest` Functions | no automatic decision | The raw header is forwarded; application code owns custom-backend verification |
| Callable Functions | no | Per-function callable policy applies |

Bypass is an explicit `Bypass` credential state produced only after route classification and successful authentication of the route's separate privileged credential. Raw `Authorization: Bearer owner`, dialect-like paths, and a download-token query parameter are not themselves sufficient. A Storage download token is compared in constant time and must bind exactly to the resolved bucket, decoded object name, and current object generation before bypass. Absence of a ruleset, use of anonymous Auth, loopback source, `demo-` project naming, or possession of an API key is not an App Check bypass.

Adapters produce the decision at their existing product boundary: Firestore requires its exact owner credential after resolving a Firestore method and target database; Identity Toolkit requires the exact owner credential after resolving an Admin-only route; Storage requires its existing JSON API/Admin dialect classification before any rules bypass; download URLs require a successfully resolved Firebase download operation plus the object-bound token check. No generic middleware may convert an owner-shaped header or path fragment into `Bypass`. Contract tests enumerate the concrete protected and privileged route tables and include client/Admin dialect-confusion attempts.

### 12.3 Atomic policy snapshot

A request captures its target project, baseline mode, registered-app view, and session epoch at admission. Reconfiguration or reset either occurs before that snapshot or causes the existing admission barrier to reject the stale request. One request must not observe a mixture of old and new policy.

An App Check denial occurs before any state mutation, event enqueue, upload-session creation, function concurrency slot, function invocation, Auth rate-accounting side effect, or Security Rules document-access budget consumption.

## 13. Product-specific behavior

### 13.1 Cloud Firestore

All Firebase client surfaces are covered:

- unary gRPC;
- `Write` and `Listen` gRPC streams;
- Firestore REST;
- browser WebChannel.

Unary requests classify `x-firebase-appcheck` metadata once. gRPC streams classify the opening metadata once and retain the resulting app identity and policy snapshot for that stream. Token expiry or policy changes do not retroactively terminate an admitted stream; reconnecting creates a new admission.

WebChannel classifies the opening request and binds the channel to the admitted app ID and epoch. Later envelopes may omit the header and reuse the channel admission. A presented replacement token must be valid for the same app and current channel epoch. A different app ID or invalid replacement closes the channel with the selected error.

App Check denial maps to gRPC `PERMISSION_DENIED` and Firestore REST HTTP 403 with stable `fireemu-code` metadata. The external message remains compatible with the SDK's permission-denied handling. Exact production wording remains a conformance fixture rather than a hard-coded claim.

App Check does not populate Security Rules `request.auth` and does not create a new Rules variable. Rules execute only after baseline admission succeeds or is allowed by `unenforced` mode.

### 13.2 Cloud Storage for Firebase

Baseline enforcement applies to the Firebase Storage dialect for metadata, list, upload, download without a valid download token, update, and delete operations. Privileged JSON API traffic and valid download-token URLs follow the bypass matrix.

Every mutating resumable-upload request is checked. Upload initiation stores the admitted app ID and epoch in the upload session. Continuation and finalization require a valid token for the same app when the current captured policy is enforced. A failed continuation does not delete or advance the upload session. This is intentionally stricter than relying only on the initiation header and must be marked `boundary-conformance` until a production fixture establishes the exact behavior.

The Storage header allowlist and CORS preflight defaults shall include `x-firebase-appcheck`. App Check denial returns the Firebase Storage JSON error envelope with HTTP 403 and a stable internal reason code. No object generation, metadata change, upload offset, or Storage event may result from the denied request.

### 13.3 Firebase Authentication

Baseline enforcement applies to end-user Identity Toolkit and Secure Token operations handled by the emulator. It does not apply to Admin SDK routes, emulator inspection routes, control routes, App Check exchange, or JWKS.

App Check is evaluated independently from the Firebase Auth credential being created, refreshed, linked, or consumed. In particular, token refresh is not an App Check bypass. A denied Auth request must not create a user, issue or rotate Auth credentials, consume an OOB code, consume a phone verification code, change MFA state, or increment a modeled abuse counter.

The initial route classification shall be published in tests. Exact production coverage of individual Identity Toolkit operations is a conformance debt because App Check for Authentication requires Identity Platform and the public documentation defines product enforcement more clearly than per-method wire behavior.

### 13.4 Callable Cloud Functions

The Functions proxy owns App Check signature verification before the request reaches the Node runner. Because the installed `firebase-functions` debug switch skips both App Check and Firebase Auth verification, the trusted callable protocol verifies and sanitizes both credentials before enabling that switch. It always classifies a presented callable App Check token, even though enforcement remains inside the callable wrapper:

- a valid token is forwarded unchanged;
- an invalid token is removed before forwarding;
- a missing token remains missing;
- the daemon records whether the original state was valid, invalid, or missing.

For callable `Authorization`, the daemon accepts only a Firebase ID token verified by the existing emulator Auth verifier and resolved as `Principal::User`. `Principal::Owner`, `Bearer owner`, service credentials, and every other non-ID-token credential are not callable user identities and are never reinserted. The proxy removes every case-insensitive caller-supplied Authorization field, rejects duplicate or folded values as invalid, and reinserts exactly one original Firebase ID token only after verification succeeds. Missing and invalid Auth credentials reach the wrapper without Authorization and therefore cannot populate callable Auth context. The proxy records the original classification without exposing the credential. A forged Auth JWT or owner credential must never become v1 `context.auth` or v2 `request.auth` merely because App Check support is active.

The runner sets `FIREBASE_DEBUG_MODE=true` and enables only the `skipTokenVerification` debug feature required by `firebase-functions` when the callable trusted protocol is active. The runner is bound to loopback, protected by a CSPRNG-generated per-runner secret, and accepts requests only from the daemon proxy. The daemon removes all caller-supplied runner-secret fields before inserting exactly one trusted value. Startup fails if the installed `firebase-functions` version changes the debug-feature semantics or the runner cannot prove loopback binding. This arrangement makes the daemon the sole trust boundary for both decoded credentials: the SDK wrapper may decode forwarded tokens without contacting hard-coded Google endpoints, but it never receives an unverified Auth or App Check token from ingress.

For a valid token, v2 `request.app` and v1 `context.app` contain the app ID and decoded claims. When the callable declares `enforceAppCheck: true`, missing or invalid input returns the callable `UNAUTHENTICATED` envelope before the user handler runs. An ordinary request receives the wrapper-compatible HTTP 401 JSON response; an exact v2 streaming request receives the wrapper-compatible HTTP 200 response containing one SSE error record. When enforcement is false or omitted, missing or invalid input invokes the handler with `app` undefined. Raw `onRequest` functions preserve `X-Firebase-AppCheck` and receive no automatic verification context.

`consumeAppCheckToken: true` is unsupported in the initial delivery. Current `firebase-functions` keeps the option inside the callable wrapper's closure (v1 and v2 alike; `__endpoint.callableTrigger` is an empty object), so reading `__endpoint` / `__trigger` cannot reveal it. Discovery therefore needs a version-bounded loader instrumentation in the runner (wrapping the `onCall` exports of the installed, supported `firebase-functions` versions before user code loads, capturing the options) or an explicit trusted runner protocol extension. The fail-closed interpretation is three-valued: `true` obtained → discovery fails with `APP_CHECK_REPLAY_UNSUPPORTED`; `false` obtained reliably → callable App Check may be enabled; the value cannot be obtained → starting Functions with App Check enabled fails at startup. The value is never guessed as `false`, because a hidden `consumeAppCheckToken: true` would otherwise run with `alreadyConsumed: false`. Unknown metadata shapes are startup errors, not warnings.

## 14. Lifecycle, sessions, reset, and snapshots

Static app registrations and static debug-token digests are configuration and survive project reset. Dynamically registered debug tokens belong to the project registry and are removed when that session project is deleted. Apps cannot be registered dynamically in the initial delivery. `POST /v1/sessions` does not register apps, but a session whose project ID is statically configured in `appCheck.apps` uses that registration; a project without a static registration cannot use App Check, and adding one requires configuration and a daemon restart in the initial delivery (accepting `appCheck.apps` in the session creation body is a later feature).

Reset, restore, and project deletion advance or replace the project App Check epoch. All previously issued tokens then fail with `WrongEpoch`. Issued tokens, raw debug secrets, private signing material, instance secrets, and epochs are never serialized.

The existing in-memory atomic snapshot hook captures dynamic debug-token IDs, metadata, and digests as sensitive process memory. Restore replaces the dynamic debug-token registry rather than merging it: registrations created after the snapshot disappear, registrations deleted after the snapshot return, and then a fresh epoch is generated before admissions resume. Static registrations still come from current canonical configuration. Any future on-disk snapshot export is a separate capability and must omit debug-token digests until it defines an explicitly requested, access-controlled sensitive format with restrictive file permissions. It must never silently redact a digest while claiming credential-state fidelity.

Observation counters reset with project state. Future replay-consumption state must either be included atomically in a snapshot or be invalidated by an epoch change; it may never be silently cleared while old limited-use tokens remain valid.

## 15. Observability and UI contract

Each classified request produces a structured observation with:

- project ID;
- service and transport;
- operation or callable function name;
- baseline mode;
- credential category: `bypass`, `missing`, `valid`, `invalid`, or future `reused`;
- stable failure reason for privileged views;
- app ID for valid tokens;
- logical timestamp and non-secret policy-generation number;
- admitted or denied outcome.

Observations must not contain a raw JWT, JWT signature, raw debug secret, full debug-secret digest, private key, instance secret, epoch value, or `Authorization` credential. Unprivileged logs collapse detailed invalid reasons to `invalid`.

The control API exposes per-project counters by service, verified app ID, category, and outcome. Every observation and counter endpoint requires the control token for every HTTP method even when `Origin` is absent, sets `Cache-Control: no-store`, and aggregates unverified app IDs into a bounded `unknown` label. The Emulator UI may add an App Check page after the API stabilizes. UI absence does not block the initial core capability, but the capability manifest must say whether only the control API is available.

## 16. Security requirements

The following are merge-blocking invariants:

- `INV-APPCHECK-001 NoAdmissionAfterFailedVerification`: an `ENFORCED` request with `Missing` or `Invalid` App Check state never reaches product logic.
- `INV-APPCHECK-002 ProjectAndAppBinding`: a token issued for one project or unregistered app never authorizes another project or app registration.
- `INV-APPCHECK-003 NoSideEffectsAfterDenial`: denied requests create no persistent state, events, function invocations, upload progress, or credential rotation.
- `INV-APPCHECK-004 SecretRedaction`: raw debug secrets, private keys, and raw JWTs never appear in trace, snapshot, log, UI, or error output.
- `INV-APPCHECK-005 OnePolicySnapshot`: one request is decided under one coherent mode, registry view, and session epoch.
- `INV-APPCHECK-006 RunnerTrustBoundary`: the Functions runner cannot be reached without the per-runner secret, and it decodes only tokens prevalidated by the daemon.
- `INV-APPCHECK-007 ResetInvalidatesTokens`: a token admitted before an epoch swap cannot be admitted after it.
- `INV-APPCHECK-008 AtMostOneConsumption`: once replay protection exists, concurrent consumption marks at most one request as first use.
- `INV-APPCHECK-009 OneCanonicalHeader`: duplicate, folded, oversized, or ambiguous App Check headers never reach product logic or the Functions runner as a valid credential.
- `INV-APPCHECK-010 CallableAuthIntegrity`: activating callable App Check support never causes an unverified Auth token to populate callable Auth context.
- `INV-APPCHECK-011 InstanceIsolation`: normally started daemon instances never accept each other's locally issued tokens.
- `INV-APPCHECK-012 PrivilegedRouteAuthentication`: management and detailed-observation routes require the control token independently of origin and method.

Debug secrets are credentials even in a local emulator. Documentation and examples must use clearly fake values, store only digests, and warn against reusing a production Firebase App Check debug token.

## 17. Error contract

Internal reason codes are stable and machine-readable:

- `APP_CHECK_REQUIRED`
- `APP_CHECK_MALFORMED`
- `APP_CHECK_BAD_SIGNATURE`
- `APP_CHECK_EXPIRED`
- `APP_CHECK_WRONG_PROJECT`
- `APP_CHECK_UNKNOWN_APP`
- `APP_CHECK_WRONG_EPOCH`
- `APP_CHECK_REPLAY_UNSUPPORTED`

Public enforced responses may collapse these to `APP_CHECK_INVALID` where distinguishing them would expose registry state. Detailed codes are emitted only through privileged observations and test hooks.

Product mapping is:

| Surface | Missing or invalid under enforcement |
|---|---|
| Firestore gRPC and streams | `PERMISSION_DENIED` with `fireemu-code` metadata |
| Firestore REST and WebChannel | HTTP 403 Google JSON `PERMISSION_DENIED` |
| Firebase Storage dialect | HTTP 403 Firebase Storage JSON error |
| Firebase Auth client route | HTTP 403 Google JSON `PERMISSION_DENIED` |
| Callable Functions | HTTP 401 callable `UNAUTHENTICATED` JSON envelope; exact v2 streaming requests receive HTTP 200 with one `UNAUTHENTICATED` SSE error record |
| Exchange invalid attestation | HTTP 403 `PERMISSION_DENIED`, `App attestation failed.` |
| Exchange malformed request | HTTP 400 `INVALID_ARGUMENT` |
| Unsupported limited-use exchange | HTTP 501 `UNIMPLEMENTED` |

These mappings are `boundary-conformance` until the conformance scenarios record and approve the corresponding real-service behavior.

## 18. Coverage obligations

| ID | Obligation | Planned evidence | Initial ledger status |
|---|---|---|---|
| `AC-CAP-001` | Capability status, supported surfaces, bypasses, precision, and divergences are public | capability manifest test | debt |
| `AC-CFG-001` | Defaults preserve current behavior; invalid keys, types, modes, TTLs, app IDs, project numbers, and hashes fail closed | schema and config unit tests | debt |
| `AC-TOKEN-001` | Valid, malformed, forged, expired, future-issued, wrong-key, wrong-project, unknown-app, disabled-app, and wrong-epoch tokens classify correctly | core unit and property tests | debt |
| `AC-EXCHANGE-001` | Only a constant-time digest match produces a token; invalid app and secret are externally indistinguishable | HTTP integration tests | debt |
| `AC-HEADER-001` | Every transport rejects duplicate, folded, empty, oversized, and ambiguous App Check headers consistently | adapter and proxy integration tests | debt |
| `AC-BOUNDARY-001` | Enforcement denial occurs before Rules and every side effect | independent integration tests for each product | debt |
| `AC-FS-001` | Unary gRPC, Write, Listen, REST, and WebChannel obey the same matrix and stream-lifetime contract | real-listener adapter tests | debt |
| `AC-ST-001` | Metadata, list, upload, resumable continuation/finalization, download, update, delete, JSON API bypass, and download-token bypass are explicit | Storage adapter tests | debt |
| `AC-AUTH-001` | End-user Auth routes enforce; Admin/emulator routes bypass; denial does not consume credentials or action codes | Auth HTTP tests | debt |
| `AC-FN-001` | Valid callable context, enforced missing/invalid rejection, unenforced undefined context, callable Auth integrity, onRequest passthrough, and unsupported consume detection | runner integration and SDK smoke | debt |
| `AC-SDK-001` | Real Web SDK obtains a local token through `CustomProvider` and sends it to Firestore, Storage, Auth, and callable Functions | SDK smoke | debt |
| `AC-LIFE-001` | reset, restore, deletion, and session isolation invalidate or isolate tokens and counters as specified | session integration tests | debt |
| `AC-OBS-001` | metrics distinguish valid, missing, invalid, bypass, admitted, and denied without exposing secrets | control/UI API tests | debt |
| `AC-CONF-001` | Selected production and official-emulator fixtures record header handling, failures, bypasses, and callable context | opt-in conformance suite | suggested pending approval |
| `AC-TRACE-001` | Critical invariants map to integration, mutation, and applicable formal or concurrency artifacts | traceability validator | debt |
| `AC-REPLAY-001` | limited-use tokens are consumed atomically and callable `alreadyConsumed` is correct | Quint, Loom, integration, and mutation tests | out of initial scope |

High-risk obligations require at least two independent checks or an explicit documented exception. In particular, project binding, no side effects after denial, runner trust, redaction, and future replay consumption require both a focused test and a cross-layer or model-based check.

## 19. Required test scenarios

Scenario names in the public repository shall be English and describe the observable behavior.

### Core and exchange

1. `a registered debug token exchanges for a project-bound RS256 session token`
2. `an unknown debug token and an unknown app produce indistinguishable public errors`
3. `a token expires exactly when the virtual clock reaches exp`
4. `a token issued in the future is rejected`
5. `a valid signature with another project audience is rejected`
6. `a registered app from another session cannot authorize this session`
7. `reset invalidates every token from the previous epoch`
8. `limited-use exchange fails closed while replay protection is unsupported`
9. `issuer prefix and suffix confusion cannot satisfy exact issuer validation`
10. `uppercase UUID input exchanges against its canonical registered digest`
11. `concurrent exchanges produce unique token IDs`
12. `two normal daemon instances reject each other's locally issued tokens`
13. `the canonical configuration example passes schema and loader validation`
14. `conflicting project ID and project number mappings fail configuration`
15. `one app ID cannot be reused across projects`

### Enforcement matrix

For each Auth, Firestore, and Storage surface, cover the Cartesian matrix of baseline mode (`off`, `unenforced`, `enforced`) and credential state (`missing`, `valid`, `malformed`, `bad signature`, `expired`, `wrong project`, `unknown app`, `bypass where applicable`). Pairwise generation may reduce redundant transport combinations only after every obligation remains mapped.

### Firestore

1. `enforced unary Firestore rejects a valid Auth user without App Check before Rules evaluation`
2. `unenforced Firestore admits an invalid App Check token without creating an app identity`
3. `an admitted gRPC stream remains admitted after token expiry until reconnect`
4. `a WebChannel rejects a replacement token from another app`
5. `owner traffic follows the explicit App Check bypass`

### Storage

1. `an enforced upload without App Check creates no upload session`
2. `a resumable continuation from another app does not advance the offset`
3. `token expiry during a resumable upload preserves the resumable state`
4. `a valid download-token URL follows the explicit bypass`
5. `privileged JSON API traffic follows the explicit bypass`

### Authentication

1. `an enforced sign-up without App Check creates no user`
2. `an enforced refresh without App Check does not rotate credentials`
3. `an enforced MFA finalize without App Check does not consume the assertion`
4. `Admin account management follows the explicit bypass`

### Functions

1. `an enforced callable rejects a missing App Check token before invoking the handler`
2. `an invalid callable token is removed before runner-side unsafe decoding`
3. `a valid callable exposes the app ID and decoded claims`
4. `an unenforced callable invokes the handler with app undefined for invalid input`
5. `onRequest receives the original App Check header without automatic enforcement`
6. `consumeAppCheckToken fails function discovery while replay support is unavailable`
7. `a forged Auth token never populates callable Auth context when App Check is active`
8. `mixed-case duplicate App Check headers never reach runner-side decoding`
9. `Bearer owner never populates callable Auth context`
10. `an enforced streaming callable returns the SDK SSE error without invoking the handler`

### Management, lifecycle, and observations

1. `debug-token management requires the control token without an Origin header`
2. `read-only observations reject a missing or wrong control token`
3. `snapshot restore replaces post-snapshot debug-token registrations and rotates the epoch`
4. `unknown token input does not create an unbounded metrics label`
5. `a session reads only its own project's observations`
6. `heavy traffic to one project never evicts another project's observations`

## 20. Verification strategy

The first implementation should follow test-driven vertical slices:

1. core claims, verification, project binding, virtual-clock boundaries, and redaction;
2. configuration and capability declaration;
3. exchange and JWKS with a raw HTTP integration test;
4. Firestore unary admission as the first product slice;
5. Storage and Auth admission;
6. callable Functions and runner trust boundary;
7. streams, WebChannel, and resumable uploads;
8. real Web SDK smoke and control metrics;
9. opt-in production conformance fixtures;
10. replay protection as a separate capability.

Property-based tests are appropriate for compact-JWT parsing, base64url input, time boundaries, project/app identifiers, and header normalization. A small Quint model with a Quint Connect driver is appropriate when runtime policy reconfiguration or limited-use token consumption is implemented. The model should check `NoAdmissionAfterFailedVerification`, `OnePolicySnapshot`, and `AtMostOneConsumption`, with semantic source mutations recorded by the Quint evidence pipeline. These tools are planned verification, not evidence already produced by this specification.

Suggested semantic mutants include:

- `M-APPCHECK-001`: accept a token after signature verification fails;
- `M-APPCHECK-002`: omit project audience validation;
- `M-APPCHECK-003`: treat `now == exp` as valid;
- `M-APPCHECK-004`: run Rules before App Check denial;
- `M-APPCHECK-005`: preserve validity across epoch reset;
- `M-APPCHECK-006`: forward an invalid token to the Functions runner;
- `M-APPCHECK-007`: advance a resumable upload after denial;
- `M-APPCHECK-008`: expose a raw debug secret in list or trace output;
- `M-APPCHECK-009`: allow two concurrent first consumptions when replay protection is added.

## 21. Delivery gates

### Milestone AC0: core and exchange

`APPCHECK-CORE-1`, `APPCHECK-DEBUG-EXCHANGE-1`, and `APPCHECK-JWKS-1` pass focused tests. No Firebase product claims enforcement yet.

### Milestone AC1: baseline product enforcement

Auth, Firestore unary/REST, and Storage non-resumable operations pass the full mode and credential matrix. Capability precision remains `boundary-conformance`.

### Milestone AC2: long-lived operations and callable Functions

Firestore streams, WebChannel, resumable Storage, and callable Functions pass their lifetime and no-side-effect scenarios. Real Web SDK smoke succeeds offline.

### Milestone AC3: observation and conformance

Structured counters, capability output, and bounded real-service fixtures exist. Precision may be raised only for behaviors supported by approved evidence.

### Milestone AC4: replay protection

`APPCHECK-REPLAY-1` requires a trusted callable-context transport, atomic consumption, concurrency tests, a bounded state model, and mutation evidence. It is not implied by baseline support.

## 22. Acceptance criteria for advertising support

The project may change App Check from `unsupported` to `implemented` only when all of the following are true:

- the canonical schema and loader agree and preserve the default-off compatibility contract;
- local debug exchange produces a token accepted by the common verifier and rejected after expiry or epoch change;
- forged, wrong-project, and unknown-app tokens fail on every supported ingress;
- Auth, Firestore, and Storage implement all three baseline modes and the bypass matrix;
- callable `enforceAppCheck` behavior and app context pass with supported `firebase-functions` versions;
- unsupported `consumeAppCheckToken` fails closed;
- denied operations demonstrate no side effects;
- reset and session isolation tests pass;
- traces, snapshots, logs, errors, and UI/API output pass secret-redaction tests;
- the real Web SDK smoke passes without contacting a production App Check endpoint;
- capability output states exact surfaces, precision, known divergences, and replay status;
- the security review has no open Must Fix item.

## 23. Known conformance debt

The following behaviors require bounded real-service fixtures before their precision can exceed `boundary-conformance`:

- exact Firestore, Storage, and Auth error messages and metadata;
- the exact list of Identity Toolkit and Secure Token methods protected by App Check for Authentication;
- App Check behavior for an already open Firestore stream when a token expires or enforcement changes;
- App Check checks on each Storage resumable-upload continuation;
- public Storage download-token behavior while App Check is enforced;
- service-account and Admin bypass details by product;
- extra claims on production limited-use tokens;
- SDK behavior across selected Web, Android, Apple, and Flutter versions.

Until these fixtures exist, the specified local behavior in this document is normative for `fireemu` and must be published as such rather than presented as exact production emulation.

## 24. References

- [Firebase App Check REST API](https://firebase.google.com/docs/reference/appcheck/rest)
- [Exchange a debug token](https://firebase.google.com/docs/reference/appcheck/rest/v1/projects.apps/exchangeDebugToken)
- [App Check token response](https://firebase.google.com/docs/reference/appcheck/rest/v1/AppCheckToken)
- [Verify App Check tokens from a custom backend](https://firebase.google.com/docs/app-check/custom-resource-backend)
- [Decoded App Check token claims](https://firebase.google.com/docs/reference/admin/node/firebase-admin.app-check.decodedappchecktoken)
- [Enable App Check enforcement](https://firebase.google.com/docs/app-check/enable-enforcement)
- [App Check enforcement modes](https://firebase.google.com/docs/reference/appcheck/rest/v1/EnforcementMode)
- [Enable App Check enforcement for Cloud Functions](https://firebase.google.com/docs/app-check/cloud-functions)
- [Monitor App Check request metrics](https://firebase.google.com/docs/app-check/monitor-metrics)
- [Use the debug provider in web apps](https://firebase.google.com/docs/app-check/web/debug-provider)
- [Firebase Admin Node App Check verifier](https://github.com/firebase/firebase-admin-node/blob/main/src/app-check/token-verifier.ts)
- [Firebase Functions callable App Check handling](https://github.com/firebase/firebase-functions/blob/master/src/common/providers/https.ts)

## 25. Review decisions (2026-08-30)

Decisions taken on the implementation review, applied to the sections above:

1. The App Check key is generated from the OS CSPRNG once per daemon instance; the test seam is constructor injection (`AppCheckKeySource` / signer factory), not a configuration field. `tokenSigning` is `instance-rsa`.
2. No cryptographic primitive lives in `fireemu-core-app-check`: SHA-256 and constant-time comparison come from standard crates behind core-defined traits implemented by the shell; the Rules hashing implementation is not reused. `jti` is epoch plus an atomic counter, authenticated by the JWT signature itself.
3. The callable trusted protocol verifies the Authorization ID token against the target project's `AuthRegistry` and the virtual clock, admits only `Principal::User` (never `Bearer owner`), rejects duplicate Authorization fields, and strips every original Authorization before reinserting exactly one verified token; the unsafe decoder in `firebase-functions` fills `uid` from `sub`, so RS256 session tokens populate callable context too.
4. `consumeAppCheckToken` detection is three-valued and fail-closed as described in section 13.4; an undeterminable value fails Functions startup with App Check enabled.
5. Sessions: only projects with a static `appCheck.apps` registration can use App Check; `POST /v1/sessions` neither registers apps nor blocks a statically registered project.
6. One App Check key per daemon; concurrent generation with the Auth session key when both are enabled.
