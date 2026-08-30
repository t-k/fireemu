# firebase-testd

A deterministic, test-only local runtime for Firebase SDK and Functions code, written in Rust.

`firebase-testd` is not a faster re-implementation of the Firebase Emulator Suite. Its core is a
deterministic state machine that:

- detects missing Firestore indexes, production limit violations and inefficient queries locally;
- isolates state, events, time and Function execution per project / session so that parallel
  tests are deterministic;
- runs scheduled Functions against a virtual clock and offers `await-idle` instead of `sleep`;
- reproduces retries, duplicate delivery, delays and conflicts as seeded fault injection;
- treats Firestore, Security Rules and Enterprise / Text Search limits as versioned,
  boundary-exact specifications rather than documentation values;
- never claims compatibility it cannot show: every feature is declared in a Capability
  Manifest with an explicit precision (`exact`, `boundary-conformance`, `estimated`,
  `oracle-only`, `unsupported`).

## Status

Implemented: Milestone A (verification-ready core), Milestone B (strict Firestore gateway: query / index / limit validation), Milestone D core (`ST-OBJ-1`: Cloud Storage objects with generations, listing, resumable uploads on both the Firebase and the JSON API protocols; Storage Security Rules evaluated at upload finalization against the received bytes), Milestone E (local Firestore execution: versioned documents, atomic commits with preconditions / masks / transforms, MVCC transactions with read-set and query re-validation, queries, aggregations, `Write` and `Listen` streams), `FS-REST-1` (the Firestore REST API on the same port as gRPC), Milestone H0 (Auth over the Identity Toolkit REST subset: password / anonymous / custom token / email link / phone / fixture identity provider sign-in, email actions with codes readable from `/emulator/v1/projects/{p}/oobCodes`, TOTP and phone second factors, Admin SDK account endpoints) native Security Rules enforcement on every Firestore surface (`Bearer owner` bypass, ID tokens verified against the Auth store, reads checked against the returned snapshot, writes checked inside the commit, queries proven from their constraints; see `RULES-QUERY-CONSTRAINTS` in `crates/ftd-adapter-grpc/src/rules.rs`), and Milestone C (Cloud Functions: a `firebase-functions` v2 codebase runs in the bundled Node runner; Firestore document triggers, Storage object triggers, `onSchedule` driven by the virtual clock, `onRequest` / `onCall` over an HTTP port, retries with virtual-time backoff, `await-idle`).

The real `firebase-admin`, `firebase` (Node: gRPC streams; browser: the WebChannel transport on the same port), and `firebase/firestore/lite` (REST) SDKs run against the daemon; `tools/sdk-smoke` holds the smoke scripts and a browser page. Rules cover `get()` / `exists()` / `getAfter()`, the `timestamp` / `duration` / `latlng` / `math` / `hashing` namespaces, `map.diff()`, query proofs from equality / `in` / `!=` / `not-in` / array / range constraints and `request.query`, and `firestore.get()` in Storage rules. `Listen` resumes from a token or read time by replaying only the changes since (MVCC history), and `PartitionQuery` splits collection groups for parallel readers. A target whose own query is refused (a missing composite index, a malformed query) is removed with its cause -- `TargetChange REMOVE` carrying `FAILED_PRECONDITION` and the actionable index diagnostic -- on both gRPC and WebChannel, and the stream stays open for its other targets; a stream-level error is reserved for session-wide or database-wide failures. Not implemented yet: `ExecutePipeline`, Storage object versioning / signed URLs / compose.

## Run

```sh
cargo run -p firebase-testd -- up --firestore-port 8080 --http-port 9099 --storage-port 9199
#   optional: --config firebase-testd.json  (see spec/config/firebase-testd.schema.json)
#   optional: --functions ./functions --functions-port 5001   (a firebase-functions v2 codebase)
#   optional: --firebase-json firebase.json --project my-app   (rules, indexes, ports from a Firebase project)
```

`firebase-testd exec` is the `firebase emulators:exec` equivalent: it serves the same, runs a command once every listener is bound, stops everything when the command exits and exits with its status.

```sh
firebase-testd exec --firebase-json firebase.json --project my-app --only auth,firestore,storage -- vitest run
```

The command receives `FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST`, `FIREBASE_STORAGE_EMULATOR_HOST` / `STORAGE_EMULATOR_HOST` (those named by `--only`; every service listens regardless), `FTD_FUNCTIONS_HOST` when a functions codebase is loaded, `GOOGLE_CLOUD_PROJECT` / `GCLOUD_PROJECT`, and `FTD_CONTROL_TOKEN` / `FTD_CONTROL_URL` for the control API. SIGINT and SIGTERM are forwarded to the command (its status becomes `128 + signal`) and nothing is left listening or running. `--firebase-json` maps `firestore.rules`, `firestore.indexes`, `storage.rules`, `emulators.*.port` and, when `functions` is selected, `functions.source`; entries without an equivalent (`emulators.pubsub`, `database`, ...) are named in a notice and ignored. Ports given on the command line override it.

The daemon prints the environment variables SDKs need (`FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST`, `FIREBASE_STORAGE_EMULATOR_HOST` / `STORAGE_EMULATOR_HOST`). Storage rules load from `storage.rules` in the config or `PUT /v1/storage/rules`. Security Rules come from `rules.source` in the config file or at runtime:

```sh
curl -X PUT http://127.0.0.1:9099/v1/rules -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s firestore.rules '{source: $s}')"
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 60}'
curl -X POST http://127.0.0.1:9099/v1/sessions/default/reset   # drop Firestore + Auth state
curl -X POST http://127.0.0.1:9099/v1/sessions/default/snapshots -d '{"name": "seeded"}'          # capture everything
curl -X POST http://127.0.0.1:9099/v1/sessions/default/snapshots/seeded:restore                  # put it back, atomically
curl -X PUT  http://127.0.0.1:9099/v1/sessions/default/faultPlan -d '{"rules": [{"match": {"operation": "firestore.commit", "nth": 2}, "action": {"type": "returnError", "code": "ABORTED"}}]}'
```

Sessions are isolated by project: `POST /v1/sessions -d '{"project": "demo-b", "buckets": ["extra-bucket"], "apiKeys": ["key-b"]}'` gives `demo-b` its own Firestore databases, Storage buckets (its `demo-b.appspot.com` / `demo-b.firebasestorage.app` plus the ones it declares), Auth store, fault plan, snapshots and text indexes. Admin SDK routes under `projects/demo-b/...` use its store; client SDK routes reach it through a declared API key (`?key=key-b`), the audience of the ID token they carry, or the refresh token they present. ID tokens are accepted only by the project of their audience (a `demo-b` token on `demo-app` data or buckets is `UNAUTHENTICATED`, as in production). `POST /v1/sessions/demo-b/reset` wipes only that project, `DELETE /v1/sessions/demo-b` removes it, and a reset of `default` wipes everything except the registered sessions; the clock, rules and functions are shared by every session. A reset and a deletion are all or nothing: every store they will write is checked first, and one that refuses answers `INTERNAL` with the store named while the session keeps its data, its registration and its snapshots.

Snapshots copy what the session owns (its Firestore databases, Storage objects, Auth users, fault plan and text indexes) and, for the default session, the shared parts (the clock, both rulesets, the auto-ID generator) in one exclusive section (a restore of the default session is a new epoch: streams end, the functions runtime resets; outstanding functions work is not captured); they live in memory. A capture is all or nothing too: every part is copied before any of it is retained, so a store that cannot be read refuses the snapshot instead of retaining an empty part. A restore validates every part, takes a pre-image of every store and only then applies them in order; a store that refuses the apply is reported and the stores already written are put back, so the session is never half of one snapshot and half of another. Each session retains at most 16 named snapshots, since each one is a full copy of what the session owned: a seventeenth name is `RESOURCE_EXHAUSTED` (429) and changes nothing, while capturing over a name the session already holds is always admitted and releases the copy it held. `GET /v1/sessions/{s}/snapshots` reports `retained`, `limit` and `remaining`. Fault plans (spec 18) name an operation (`firestore.commit` / `read` / `beginTransaction`, `storage.upload` / `read` / `delete` / `list`, `functions.invoke` / `deliver`; a rule with only an `eventType` is a `functions.deliver` rule), optionally the nth occurrence (counted per function when one is named) and a function, and an action that applies to that operation (`returnError` with a gRPC name or HTTP code, `delay` seconds, `duplicate` count, `crashRunner`, `timeout`, `deadLetter`, `transactionConflict`, `dropConnection`); a combination the adapters would ignore is refused. `functions.invoke` rules also apply to HTTP invocations and to scheduled or manual runs; a `delay` holds an event until the virtual clock reaches the instant and then applies the other actions of the rule set. `dropConnection` closes the connection (or resets the gRPC stream) instead of answering on the Firestore, Storage and functions ports; over WebChannel it is reported as `UNAVAILABLE`, and for event invocations it is a failed attempt. `GET .../faultPlan` shows what fired.

Without rules every request is allowed (the daemon says so at start). `firebase-testd doctor` prints versions and catalogs; `firebase-testd capabilities` prints the Capability Manifest.

### Emulator UI

The daemon serves an Emulator UI on `--ui-port` (default 4000, best effort: a busy port only disables it; `--ui-port 0` turns it off) at `http://127.0.0.1:4000/ui`: an overview, a Firestore data browser with a typed field editor and live updates, Auth users with custom claims / second factors / pending action codes, Storage objects, Functions (registered triggers, invocation history, a live log stream, manual schedule runs and Pub/Sub publishes), both rulesets, App Check (the configured apps, the baseline modes, debug tokens and the observation counters), and the runtime controls (virtual clock, snapshots, fault plans, sessions). Its API under `/ui/api/` is a same-origin, privileged front to the existing surfaces (Firestore REST as owner, the Identity Toolkit admin routes, the Storage JSON API, the App Check debug-token routes, the control API); every request to it must present the control token in `Authorization: Bearer` (the served page carries it; a query parameter is not accepted), the listener answers only to loopback `Host`s, the page ships a Content Security Policy that keeps it out of other sites' frames, object downloads through the front are always attachments, and at most 64 event streams are open at once. Functions and Pub/Sub routes belong to the default session; the Storage page lists the selected session's buckets.

The App Check page shows this instance's JWKS `kid` and token TTL, the effective baseline mode of every service, the apps registered for the selected session's project with their configured digest count against their dynamic registrations, the debug tokens of one app, and the counters and recent observations of the session. Registering a debug token returns the raw secret exactly once: the page shows it in a copyable field behind a warning and drops it when it is dismissed or the page is left. It is never stored in the browser, never put in a URL, and never appears in a list, in `window.__FTD__` or in an observation — the daemon keeps only its SHA-256 digest and cannot show it again. A runtime with `appCheck.enabled` false says so on the page instead of offering the surface.

The app lives in `ui/` (Solid, Vite, Tailwind) and is embedded into the binary at compile time; a binary built without it serves a placeholder page that says so:

```sh
pnpm -C ui install && pnpm -C ui build     # writes ui/dist (not committed)
cargo build --release -p firebase-testd    # embeds it
pnpm -C ui test && pnpm -C ui e2e          # unit tests; Playwright against a real daemon
```

### Composite indexes

`firestore.indexValidationPolicy` decides what happens to a query whose composite index is not in `firestore.indexFile`:

- `conservative` (default) and `firebase`: the query is refused with `FAILED_PRECONDITION` and the `firestore.indexes.json` fragment production would need, before it runs.
- `emulator`: the query runs as if the index existed, which is what the Firebase Emulator Suite does; the gateway records an `FS_EMULATOR_INDEX_ASSUMED` warning. Use it for projects that never maintained an index file; it says nothing about production index conformance.

### Firestore history retention

Firestore keeps every document version it may still be asked about, and drops the rest at the end of the commit that makes them unreachable. A version is retained while at least one retention root can reach it:

- **The `read_time` window.** `read_time` selectors, and read-only transactions started at a `read_time`, reach one hour back (`READ_TIME_RETENTION_SECONDS`, Firestore without PITR). The version that was current when the window opened is retained too, so a read at the very start of the window is exact. A `read_time` older than the retained history is refused with `FAILED_PRECONDITION`; it is never answered from a different version.
- **Open transactions.** Every transaction still inside its budget (`FS-LIMIT-TRANSACTION-TOTAL-TIME` / `FS-LIMIT-TRANSACTION-IDLE-TIME`) pins the version it reads at, so its snapshot stays stable across compaction. An expired transaction pins nothing: it can never read again.
- **`Listen` resume tokens.** A token names the version it was issued at and is honoured while that version is retained: the target's state is recomputed there and only the changes since are replayed. A token whose version has been compacted away (or one from another session, database, target or the future) is refused explicitly -- the target is `RESET` and replays from scratch -- so a token is never resumed against unrelated history. Resume tokens therefore live exactly as long as the `read_time` window.
- **The current state.** The newest version or tombstone of every path is always kept, so live reads and queries never change. A path whose only remaining version is a tombstone older than the window is dropped entirely: at every version that can still be asked about, it is indistinguishable from a path that never existed.

Named snapshots are independent copies, not references into the live history: restoring one reproduces exactly what it captured, whatever the live database compacted in the meantime.

Memory therefore tracks the live data plus what the retention roots pin, not the number of writes a session made. All of it runs on the virtual clock: without `clock:advance`, nothing is ever compacted, so tests see the whole history of their run.

### Clock

The virtual clock starts at the wall-clock time unless `daemon.clockStart` pins it (a pinned start keeps runs reproducible; an unpinned one keeps the ID tokens the daemon issues valid for SDKs that check expiry against real time, such as the Admin SDK's `verifyIdToken`). Either way the clock only moves through the control API afterwards.

### ID tokens

`auth.idTokenSigning` picks the token format:

- `unsigned-emulator` (default): `alg: none`, the Firebase Auth Emulator format. The Admin SDK accepts these tokens whenever `FIREBASE_AUTH_EMULATOR_HOST` is set, and it accepts nothing else in that mode.
- `session-rsa`: RS256 with a 2048-bit RSA key derived deterministically from the session seed (`kid` is the SHA-256 prefix of the modulus). The JWKS is served at `/.well-known/jwks.json` and at `/www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com` on the HTTP port, for backends that verify tokens with a JOSE library against a configurable JWKS URL. Once the signer is installed, every surface (Identity Toolkit, Firestore rules, Storage rules) refuses unsigned and foreign-signed tokens. Keep the default when the Admin SDK's `verifyIdToken` is on the path: `firebase-admin` skips key fetching in emulator mode and only accepts `alg: none`.

### App Check

`appCheck` is off by default. Enabling it turns on the local App Check issuer — the daemon registers Firebase app IDs from configuration, exchanges a registered debug secret for a locally signed RS256 token, and publishes the public key at a local JWKS endpoint — and lets `appCheck.services` enforce that token on Firebase Authentication, Cloud Firestore and Cloud Storage, while callable Functions enforce it per function. This is milestones AC0 to AC2 of [docs/specifications/firebase-app-check.md](docs/specifications/firebase-app-check.md): `APPCHECK-CORE-1`, `APPCHECK-DEBUG-EXCHANGE-1`, `APPCHECK-JWKS-1`, `APPCHECK-ENFORCE-1`, `APPCHECK-FUNCTIONS-1` and `APPCHECK-SDK-WEB-1`.

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
        "debugTokenSha256": ["db8055e0e0307d5a016bec4dc338d69875eb0fb7e614a8b125b08fb082095d98"]
      }
    ],
    "services": { "auth": "off", "firestore": "unenforced", "storage": "unenforced" }
  }
}
```

Configuration stores only the SHA-256 digest of a debug secret, never the secret itself; the digest is of the lowercase hyphenated canonical UUIDv4 text. Use clearly fake local values and never a production App Check debug token. `tokenTtlSeconds` is between 1800 and 604800, one project ID maps to exactly one project number and back, one app ID belongs to exactly one project, and a standard `1:{projectNumber}:{platform}:{opaque}` app ID must embed its own project number. Unknown keys are errors everywhere, and a non-`off` service mode while `enabled` is false is refused.

The routes share the Auth/control listener and never cache (`Cache-Control: no-store`):

```sh
# exchange a registered debug secret (the v1beta twin behaves identically; ?key= is ignored)
curl -X POST "http://127.0.0.1:9099/v1/projects/demo-app/apps/1:1234567890:web:local-test-app:exchangeDebugToken" \
     -H 'content-type: application/json' -d '{"debugToken": "<uuid>", "limitedUse": false}'
# -> {"token": "<RS256 JWT>", "ttl": "3600s"}

curl http://127.0.0.1:9099/v1/jwks            # this instance's public App Check key

# privileged: the control token is required for every method, whatever the Origin
curl -X POST "http://127.0.0.1:9099/emulator/v1/projects/demo-app/apps/1:1234567890:web:local-test-app/debugTokens" \
     -H "authorization: Bearer $FTD_CONTROL_TOKEN" -H 'content-type: application/json' \
     -d '{"displayName": "ci runner", "generate": true}'
# -> the raw secret exactly once; a later list shows only the id, name, creation time and digest prefix
```

The signing key is a dedicated 2048-bit RSA key drawn from the operating system CSPRNG once per daemon instance (`instance-rsa`); its `kid` starts with `ftd-app-check-` and it is never the Auth session key. Two normally started daemons therefore reject each other's tokens, and a restart invalidates the previous instance's JWKS. Tokens carry the production claim shape (`iss`, `sub`, both `projects/{projectNumber}` and `projects/{projectId}` audiences, `iat`, `exp`, `jti`) plus a local private `ftd_epoch` claim that binds a token to the project session epoch. Expiry is decided on the virtual clock: `iat <= now < exp`, with `now == exp` already expired.

`--only appcheck` selects the service, and `firebase-testd exec` then exports `FTD_APP_CHECK_EMULATOR_HOST=host:port` and `FTD_APP_CHECK_JWKS_URL=http://host:port/v1/jwks`. Selecting `functions` selects App Check implicitly when it is enabled. No raw debug secret is ever generated or exported implicitly.

**Enforcement.** `appCheck.services.{auth,firestore,storage}` is `off`, `unenforced` or `enforced`. `off` does no token work at all — the header is never even read. `unenforced` classifies and records every request but denies none, and a missing or invalid token never becomes an app identity. `enforced` admits only a verified token or an explicit privileged bypass; a client sends the token as `X-Firebase-AppCheck`, exactly once. Firestore covers unary gRPC, REST, the `Write` and `Listen` streams and the browser WebChannel transport; Storage covers resumable uploads as well as everything else.

**Long-lived operations.** A stream, a channel and an upload session all outlive the request that created them, so each is admitted once and keeps that admission:

| Operation | Admitted | Kept for | A later request |
|---|---|---|---|
| `Write` / `Listen` gRPC stream | opening metadata, classified once; decided as soon as the first request names the database | the stream's whole life | is not re-decided; token expiry and a policy change do not end an admitted stream. Reconnecting is a new admission |
| WebChannel | the opening init header block (`headers=` / `$httpHeaders`), plus a real HTTP field if one is sent | the channel's life; the channel is bound to the admitted app and the session epoch of that admission | may omit the field entirely. A replacement token has to be valid for the same app under the current epoch; a different app, or one that does not verify, closes the channel |
| Resumable Storage upload | the initiation, which records the admitted app and epoch in the upload session | until the session ends | continuation, status query, cancel and finalization all need a valid token for the same app. The check runs before the command is read, so a refusal neither advances nor deletes the upload, and a token that expires mid-upload leaves the resumable state intact — refresh it and resume from the offset already reached |

Only an `enforced` policy binds a channel or an upload session. Under `unenforced` a client may legitimately stop presenting a token, and binding it would enforce by the back door.

A denial happens before Security Rules and before any side effect: no user, no issued or rotated credential, no consumed action or phone code, no MFA change, no object generation, no upload session, no Firestore mutation. It renders as `PERMISSION_DENIED` with the public code in the `ftd-code` metadata on Firestore gRPC, as an HTTP 403 Google JSON error on Firestore REST and on Auth, and as the Firebase Storage JSON error envelope with 403 on Storage. The public code is `APP_CHECK_REQUIRED` or `APP_CHECK_INVALID`; the detailed reason stays in the privileged observations.

The bypasses are explicit, and each one requires that route's own credential rather than a header shape or a path fragment:

| Surface | Bypasses | The credential it must present |
|---|---|---|
| Firestore unary gRPC and REST | yes | `Authorization: Bearer owner` exactly |
| Identity Toolkit `projects/{p}/...` Admin routes | yes | `Authorization: Bearer owner` exactly |
| Auth JWKS | yes | public-key discovery; it carries no state |
| `/emulator/v1/...` inspection routes | yes | `Authorization: Bearer $FTD_CONTROL_TOKEN`. Their own guard only challenges browser requests, so the App Check path checks the token itself rather than inheriting a guard that does not run for a command-line caller |
| Control API, Emulator UI API, App Check exchange and JWKS | yes | the control token, or bootstrap and public-key discovery |
| Storage JSON API dialect (`/storage/v1/...`, Admin SDK, `gcloud`) | yes | `Authorization: Bearer owner` exactly. The dialect bypasses Security Rules without a credential, as the official Emulator does; the App Check bypass deliberately does not, or rewriting `/v0/b/...` to `/storage/v1/b/...` would defeat enforcement |
| Storage Firebase download URL | yes | a `?token=` bound in constant time to the resolved bucket, object and generation |
| Storage Firebase dialect, Auth end-user routes, Firestore end-user traffic | no | — |

Disabling Security Rules is not a bypass: with rules off every Firestore caller would otherwise be treated as the owner without presenting anything, so the App Check path verifies the owner credential itself. Neither is anonymous Auth, a loopback source, a `demo-` project name or an API key.

Reset, project deletion and snapshot restore replace the project's App Check epoch, so every token issued before the transition fails at its next verification; the observation counters reset with it. A project that has no static `appCheck.apps` registration cannot use App Check at all, so an `enforced` service denies every request that targets it.

Privileged counters and observations are at `GET /v1/sessions/{session}/appCheck/observations`, and the Emulator UI's App Check page shows them next to the configuration and the debug tokens. Unlike the rest of the control API it needs `Authorization: Bearer $FTD_CONTROL_TOKEN` for every method whether or not an `Origin` is present, and its response is `Cache-Control: no-store`. Counters are grouped by service, verified app ID, category and outcome; an unverified identity aggregates into a bounded `unknown` bucket, so nothing a caller controls becomes a label. The retained observations behind those counters are one bounded ring for the whole runtime, not one per project, so heavy traffic to one project can push another project's recent observations out of the window; the counters are derived from what the ring still holds.

**Callable Functions.** There is no `appCheck.services.functions` mode: callable enforcement is per function, as in production. Enabling App Check and selecting `functions` activates the trusted callable protocol, and the daemon proxy then owns verification for every callable request:

- `X-Firebase-AppCheck` is classified under the same contract as everywhere else. A valid token is forwarded byte for byte as exactly one field; an invalid one is removed before the runner can decode it; a missing one stays missing.
- `Authorization` is accepted only as a Firebase ID token that verifies against the target project's users on the virtual clock. `Bearer owner`, service credentials, non-`Bearer` values and duplicate or folded fields are not callable user identities and are never reinserted.
- Every caller-supplied copy of a field the daemon owns is stripped first: the App Check field, `Authorization`, the per-runner secret, and `x-callable-context-auth` / `x-original-auth` — the channels `firebase-functions` honours under its debug switch to override v1 callable auth context.
- `enforceAppCheck: true` answers the callable `401 UNAUTHENTICATED` envelope for a missing or invalid token before the runner is reached at all, so a denial costs no concurrency slot and no handler run. A valid token populates v2 `request.app` / v1 `context.app` with the app ID and the decoded claims. Ordinary `onRequest` functions get the raw field list forwarded unclassified: application code owns custom-backend verification there.

This is what lets the runner run with `FIREBASE_DEBUG_MODE=true` and only the `skipTokenVerification` debug feature. The runner is reachable only with the per-runner secret — without one it refuses every request rather than serving them unguarded — and it reports at startup which auth-override header names the installed SDK honours, so a renamed one fails startup instead of quietly escaping the proxy's strip list. With App Check active, a configured `functions.manifest` is reconciled against discovery: it may not call a real callable an `onRequest` function and route it around the boundary. That switch makes the SDK wrapper decode both credentials locally instead of calling Google — and *only* decode them, never verify — which is safe exactly because the daemon is the sole source of both.

`consumeAppCheckToken` is not readable from a deployed endpoint: v1 and v2 alike keep it inside the callable wrapper's closure. The runner therefore observes callables as they are declared, through a version-bounded loader instrumentation (supported `firebase-functions` majors: 6 and 7) that hooks `onCallHandler`, `withInit` and `wrapTraceContext` — the one path every spelling passes through, including `functions.https.onCall`, `runWith(...).https.onCall` and `onCallGenkit`. The result is three-valued and fail-closed: `consumeAppCheckToken: true` fails function discovery with `APP_CHECK_REPLAY_UNSUPPORTED` whatever else is configured, a value that cannot be determined fails startup when App Check is enabled, and it is never guessed as `false`. Startup also fails when the installed `firebase-functions` is outside the supported range or reads the debug switches differently from what the protocol assumes.

**Client integration.** Official App Check SDKs have no emulator-host switch, and `@firebase/app-check` hard-codes the production exchange endpoint, so a client uses `CustomProvider` and calls the local exchange itself. This works in a browser and in plain Node (`CustomProvider` touches no browser global, and the SDK guards its `indexedDB` token cache):

```js
import { initializeApp } from "firebase/app";
import { CustomProvider, initializeAppCheck } from "firebase/app-check";

const app = initializeApp({ projectId: "demo-app", apiKey: "fake-api-key", appId: APP_ID });
initializeAppCheck(app, {
  isTokenAutoRefreshEnabled: false,
  provider: new CustomProvider({
    getToken: async () => {
      // FTD_APP_CHECK_EMULATOR_HOST, or the Auth/control port.
      const url = `http://${host}/v1/projects/demo-app/apps/${encodeURIComponent(APP_ID)}:exchangeDebugToken`;
      const r = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ debugToken: DEBUG_SECRET, limitedUse: false }),
      });
      const { token, ttl } = await r.json();       // {"token": "<JWT>", "ttl": "3600s"}
      return { token, expireTimeMillis: Date.now() + parseInt(ttl, 10) * 1000 };
    },
  }),
});
```

The Firestore, Storage, Auth and Functions SDKs then attach the token themselves. `tools/sdk-smoke/appcheck.mjs` runs exactly this against `tools/sdk-smoke/firebase-testd.appcheck.json`. Use a clearly fake local debug secret and never a production App Check debug token.

**What is not supported.** Apps can only be registered in configuration, and adding one needs a daemon restart; the Emulator UI page manages debug tokens, not apps. The retained observations are one bounded ring for the whole runtime rather than one per project, which is why `APPCHECK-OBSERVE-1` is `partial`, and neither the control API nor the UI groups callable observations per callable. Limited-use tokens are unsupported: `limitedUse: true` fails closed with `501 APP_CHECK_REPLAY_UNSUPPORTED` and never returns a reusable token. Production attestation providers (Play Integrity, App Attest, DeviceCheck, reCAPTCHA) are out of scope; a local token proves nothing about device integrity. Precision is `boundary-conformance`: the exact wire messages are the ones documented here, not a recording of the real services. `GET /v1/capabilities` states the exact status of all nine `APPCHECK-*` capabilities.

### Storage

An object is at most 256 MiB; a request body is at most 260 MiB (the object boundary plus multipart framing) and is refused with `413` beyond that. Upload bytes are never duplicated on the way in: the request buffer is handed to the object store as it is, and a multipart data part is carved out of the same allocation, so a near-limit upload costs one payload-sized buffer, not two or three.

The request bodies buffered at the same time are admitted against a process-wide budget of 1 GiB (`ftd_adapter_http::storage_server::DEFAULT_BODY_BUDGET_BYTES`, about four near-limit uploads). An upload that does not fit is refused with `503` and `Retry-After: 1` before its buffer is allocated; a body without a `Content-Length` is charged as it grows. Every charge is released as soon as the request ends, including when the upload fails on rules, a checksum or a precondition. A failed upload publishes no object.

### Functions

`--functions <dir>` (or `functions.source` in the config) starts `tools/runner-node/index.mjs` (Node, needs the codebase's own `node_modules` with `firebase-functions` and `firebase-admin`; `express` comes with `firebase-functions`). The runner discovers the exported v2 functions and reports them; the daemon then delivers Firestore document events (`onDocumentCreated` / `Updated` / `Deleted` / `Written` with path parameters), Storage object events (`onObjectFinalized` / `Deleted` / `MetadataUpdated`) and `onSchedule` runs as JSON CloudEvents, and serves `onRequest` / `onCall` at `http://127.0.0.1:5001/{project}/{region}/{function}`. Functions declared with `retry: true` are retried with exponential backoff in virtual time; other failures are dead-lettered.

```sh
curl -X POST http://127.0.0.1:9099/v1/sessions/default:awaitIdle -d '{"timeoutSeconds": 30}'   # wait for triggers
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 600}'     # runs due schedules (and due retries)
curl -X POST http://127.0.0.1:9099/v1/sessions/default/functions/nightly:run                  # run a schedule now
curl http://127.0.0.1:9099/v1/sessions/default/functions                                      # queue status
```

Invocations have a real-time deadline (`timeoutSeconds`); a handler that overruns it is dead-lettered (or retried) but keeps its concurrency slot, and `await-idle` keeps waiting, until it actually finishes. The runner inherits only an allowlisted environment (no cloud credentials; Application Default Credentials are blocked) plus the emulator hosts. `POST /v1/sessions/{s}/reset` waits for requests in flight, wipes Firestore, Auth and Storage, and kills and restarts the runner, so a handler that was still running cannot write into the new session. Schedules accept IANA time zones with daylight-saving rules (`scheduler.defaultTimeZone`, `timeZone` on the function); `scheduler.overlap` chooses `allow` (default), `skip`, `queue` or `reject` for a run that comes due while the previous one is still queued or running. `firebase-functions/v1` firestore, storage and `pubsub.schedule` handlers are supported alongside v2.

Diagnostic retention is bounded by a fixed budget: the daemon keeps the 1000 most recent invocation records, the 500 most recent dead letters and the 1000 most recent terminal event records, and drops the older ones. `GET .../functions` and the UI show that window; the `succeeded`, `deadLettered` and `overlapRejected` counters in the queue status are cumulative and unaffected by it, so a long-running session keeps exact totals with bounded memory. Every retained record carries a monotonic sequence inside an explicit generation (a reset bumps the generation), and the UI's log stream asks only for the records after the cursor it holds; when its cursor is from another generation or older than the retained window, the stream sends a `resync` event with the current window instead of a delta with a hole in it. The browser keeps at most the 500 most recent invocation rows.

Browser pages on a loopback origin must send `Authorization: Bearer <control token>` (printed at start as `FTD_CONTROL_TOKEN`) to privileged control routes (reset, clock, rules, functions, `awaitIdle`); command-line clients need no token.

Pub/Sub topic triggers (`onMessagePublished`, v1 `topic().onPublish`) receive messages published through the control API (`POST /v1/sessions/default/pubsub/topics/{topic}:publish` with `{"messages": [{"json": {...}, "attributes": {...}}]}`, or the Pub/Sub REST shape `/v1/projects/{project}/topics/{topic}:publish` with base64 `data`). Auth user created / deleted events reach v1 `auth.user().onCreate` / `onDelete` handlers. `*WithAuthContext` Firestore triggers carry `authtype` / `authid` of the principal that committed. `scheduler.catchUp` chooses what happens to schedule runs that became due while the clock moved: `all` (default), `latest` (one run per job), `none`. `latest` and `none` compute the run they keep directly instead of walking the missed ones, so a jump of years costs the same as a jump of minutes; what they drop appears as one `skipped: catch-up ...` record per job and clock change, carrying a count that is exact up to `scheduler.maxCatchUpRuns` (1000) and reported as `at least N runs` beyond it (an `every N minutes` schedule is always counted exactly). `tools/sdk-smoke/functions.mjs` with `tools/sdk-smoke/functions-project/` exercises all of it (pin the clock with `--config tools/sdk-smoke/firebase-testd.smoke.json`: schedule counts depend on it). Not modelled: blocking identity functions (`beforeUserCreated` / `beforeUserSignedIn`), Realtime Database and Remote Config triggers (there is no such service in the daemon).

Browser apps point the web SDK at the same ports (`connectFirestoreEmulator(db, "127.0.0.1", 8080)`, `connectAuthEmulator(auth, "http://127.0.0.1:9099")`); the Firestore port serves gRPC, REST and the WebChannel transport, and both ports answer CORS preflights. `FTD_TRACE_WEBCHANNEL=1` traces the channel protocol on stderr.

| Crate | Purpose | Dependencies |
|---|---|---|
| `ftd-core-types` | validated identifiers, logical time, edition capabilities, deterministic adapters | none |
| `ftd-core-limits` | versioned limit catalogs and the warning / rejection engine | none |
| `ftd-core-session` | session lifecycle, epoch isolation, virtual clock, idle ledger | none |
| `ftd-core-events` | event state machine, retry policy, outbox | none |
| `ftd-core-firestore` | field paths, value ordering, storage-size formula, query AST + Standard limits, conservative index validator, local execution store (MVCC, transactions, queries, aggregations) | none |
| `ftd-core-rules` | Security Rules parser, static limit linter (`RULES-LINT-1`) and evaluator subset with runtime budgets | none |
| `ftd-core-auth` | users, custom claims, ID token claims, unsigned emulator tokens and the `IdTokenSigner` contract for signed ones, TOTP second factor (RFC 6238) | none |
| `ftd-core-storage` | Cloud Storage objects: opaque UTF-8 names, generations, metadata, listing, resumable uploads, MD5 / CRC32C | none |
| `ftd-core-functions` | function manifest, document path patterns, cron / App Engine schedules, CloudEvents attributes | none |
| `ftd-proto-firestore` | vendored Firestore v1 protos and checked-in generated code | prost, prost-types, tonic |
| `ftd-adapter-grpc` | Firestore v1 service: strict gateway, local backend, `Write` / `Listen` streams, Rules enforcement, optional upstream proxy | tonic, tokio |
| `ftd-adapter-http` | Identity Toolkit REST subset (sign-up, password sign-in, custom claims, TOTP MFA, refresh, Admin SDK accounts), RS256 session signing + JWKS, the Storage surface and the control API (clock, rules, capabilities, await-idle) | hyper, tokio, serde_json, rsa, sha2 |
| `ftd-adapter-functions` | runner process protocol, event dispatch with retries, scheduler, await-idle, HTTP function proxy | tokio, hyper, serde_json |
| `firebase-testd` | the daemon binary (`up`, `doctor`, `capabilities`) | tokio, serde_json |

`ftd-core-*` crates are `std`-only and forbid `unsafe` (ADR-001, ADR-007).

## Layout

```text
crates/            core crates (std-only) and, later, protocol / runtime shells
spec/limits/       versioned limit catalogs (single source of truth for limit values)
tools/             development tools; never linked into the release binary
verification/      TLA+ models, Loom scenarios, Kani harnesses, property tests, mutant and
                   requirement catalogs
docs/adr/          architecture decision records
```

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
scripts/check-core-deps.sh
cargo nextest run --workspace --profile pr
cargo run -p limit-catalog-gen -- check
cargo run -p traceability-check
cargo run -p config-schema-check
cargo run -p proto-gen -- check            # needs protoc
RUSTFLAGS="--cfg loom" cargo test -p ftd-verification-loom --release
TLA2TOOLS_JAR=/path/to/tla2tools.jar verification/tla/run-tlc.sh
```

`traceability-check` resolves every artifact the requirement ledger names: a `kani` artifact must
be a `#[kani::proof]` function under `verification/kani`, a `property` artifact a test function
under a `tests/` directory (the core ones live in `verification/property/tests`), a `fuzz`
artifact a `fuzz/fuzz_targets/<name>.rs` file, and a `conformance` artifact an existing path.
Artifacts that are decided but not written yet are written as `pending:<name>`; a pending artifact
is printed on every run and never counts as evidence. See
[docs/verification-ledger.md](docs/verification-ledger.md) for the schema and the gate.

The `pr` and `ci` profiles fail a run in which a process started by a test still holds the test's
captured stdout or stderr 30 seconds after the test process exited (`leak-timeout` in
`.config/nextest.toml`, which records how the period was measured). That signal cannot see a
process that closed or redirected those handles, so tests that start daemons or shells also assert
a process census (`crates/firebase-testd/tests/census/mod.rs`);
`crates/firebase-testd/tests/leak_fixture.rs` proves both, by running intentional-leak fixtures
through a nested nextest in their own process group and reaping them unconditionally.

TLC needs Java 21 and TLA+ Tools 1.8.0
(`sha256 eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`).
Kani harnesses live in `verification/kani` and run with `cargo kani`. Harnesses that allocate
on the heap currently fail on macOS with Kani 0.67 ("Function `malloc` with missing definition
is unreachable"); the allocation-free harnesses verify. Tracked as a known environment issue.

## Protobuf

`crates/ftd-proto-firestore/proto/` vendors the Firestore v1 protos from googleapis at the commit
in `proto/UPSTREAM_COMMIT`; `tools/proto-gen` regenerates the checked-in Rust code (ADR-008).
A normal build never runs `protoc`.

## Limit catalogs

Limit values are declared once in `spec/limits/<catalog-id>.json` and rendered into
`crates/ftd-core-limits/src/generated/` by `tools/limit-catalog-gen`. Catalogs are immutable:
when an official document changes, add a new catalog ID instead of editing an existing one.

```sh
cargo run -p limit-catalog-gen -- generate   # after editing spec/limits
cargo run -p limit-catalog-gen -- check      # CI
```

## Requirement traceability

`verification/requirements/requirements.json` maps every critical requirement to its TLA+
property, Loom scenario, Kani harness, property test, semantic mutants and integration tests.
`verification/mutants/catalog.json` and `verification/loom/scenarios.json` are the single
sources of truth for mutant IDs and Loom scenario names; `tools/traceability-check` rejects
duplicates, undefined references and critical requirements without a formal and a dynamic
artifact.

## License

Apache-2.0 (see `Cargo.toml`). A `LICENSE` file will be added before the first public release.
