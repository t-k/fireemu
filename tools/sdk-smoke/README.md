# SDK smoke tests

Exercise a running `fireemu` with the real Firebase SDKs.

`fireemu.smoke.json` pins the virtual clock and enables App Check with one registered
app and every service `unenforced`: the daemon then classifies and records every request
without denying any, which is what the Emulator UI's App Check page (and its Playwright
suite) needs, and what leaves the other smokes working without attaching a token.

- `smoke.mjs`: `firebase-admin` (Firestore over gRPC with `Bearer owner`, Auth over the
  Identity Toolkit REST subset).
- `client.mjs`: the `firebase` client SDK (Auth sign-up, Firestore `Listen` / `Write`
  streams) with Security Rules loaded through the control API.
- `lite.mjs`: `firebase/firestore/lite` (REST only) with Security Rules.
- `auth.mjs` (run it on an unpinned clock: `firebase-admin` checks token expiry against
  real time): email actions (password reset, verification, email link), phone sign-in,
  fixture identity providers, phone second factors and the Admin link generators, with the
  codes read from `/emulator/v1/projects/{p}/{oobCodes,verificationCodes}` (the Node build of
  `firebase/auth` has no phone support, so those steps use the same REST calls the browser
  SDK makes).
- `storage.mjs`: `firebase-admin` storage (JSON API) and `firebase/storage` (Firebase
  protocol, resumable uploads) with Storage Rules; needs `FIREBASE_STORAGE_EMULATOR_HOST`.
- `storage-targets.mjs`: the real Web Storage SDK uses three explicit bucket instances to
  prove that `.firebaserc` deploy targets select independent allow/deny rules and that an
  unmapped bucket fails closed. Run it with
  `fireemu exec --firebase-json tools/sdk-smoke/storage-targets/firebase.json --only storage:public -- npm --prefix tools/sdk-smoke run smoke:storage-targets`.
- `functions.mjs`: the functions in `functions-project/` (firebase-functions v2: Firestore
  and Storage triggers, `onSchedule`, `onRequest`, `onCall`, retries) driven through
  `awaitIdle` and the virtual clock; start the daemon with
  `--config tools/sdk-smoke/fireemu.smoke.json --functions tools/sdk-smoke/functions-project --functions-port 5001` (the config pins the virtual clock; schedule counts depend on it) and set
  `FIREEMU_FUNCTIONS_HOST=127.0.0.1:5001`. Run it on a fresh daemon (it fills the database).
- `pubsub.mjs`: the real `@google-cloud/pubsub` client against the Pub/Sub emulator over gRPC
  (`PUBSUB_EMULATOR_HOST`): create topic and subscription, publish, pull and ack with
  attributes, a subscription filter, ordering keys, and a message published through the wire
  protocol that reaches the `onMessagePublished` (v2) and `topic().onPublish` (v1) Cloud
  Functions in `functions-project/` (EVTINFRA-01 / EVTINFRA-02). Start the daemon serving
  Firestore, Functions and Pub/Sub:
  `fireemu exec --config tools/sdk-smoke/fireemu.pubsub.json --only firestore,functions,pubsub --functions tools/sdk-smoke/functions-project --functions-port 5001 --pubsub-port 8085 -- node tools/sdk-smoke/pubsub.mjs`.
- `appcheck.mjs`: `firebase/app-check` `initializeAppCheck` with a `CustomProvider` that
  exchanges a registered local debug secret, then Firestore, Storage, Auth and an
  `enforceAppCheck` callable with the token attached; start the daemon with
  `--config tools/sdk-smoke/fireemu.appcheck.json --functions tools/sdk-smoke/functions-project --functions-port 5001`
  (that config registers the same app as the smoke config but puts Firestore and Storage in
  `enforced`, which is what the refusal checks need) and set `FIREEMU_FUNCTIONS_HOST`.
  `FIREEMU_APP_CHECK_EMULATOR_HOST` is exported by `fireemu exec`; it defaults to the Auth
  port. No browser shims are needed: `CustomProvider` touches no browser global, and the SDK
  guards its `indexedDB` token cache. The SDK never dials the local exchange endpoint itself
  (`@firebase/app-check` hard-codes the production base URL), which is why the provider calls
  the daemon and hands the JWT back.
- `missing-index.mjs`: the `firebase` client SDK against a conservative gateway that declares
  exactly one composite index (`missing-index.indexes.json`, reached through
  `missing-index.firebase.json`). An undeclared `getDocsFromServer()` must reject with
  `failed-precondition` and the actionable diagnostic, the covered query must still succeed on
  the same client, and a raw WebChannel handshake carrying the failing `AddTarget` must answer
  the first back channel with `TargetChange REMOVE` instead of `Unknown SID` (the Node build of
  the SDK speaks gRPC, so that transport is probed directly). Run it with
  `fireemu exec --config tools/sdk-smoke/fireemu.missing-index.json --firebase-json tools/sdk-smoke/missing-index.firebase.json`.
- `recursive-delete.mjs`: `firebase-admin` recursive deletion of an empty root, a nested
  subtree and a missing root with descendants. It also verifies that an unrelated sibling is
  retained. Run it with `fireemu exec --only firestore -- sh -c 'cd tools/sdk-smoke && npm run smoke:recursive-delete'`.
- `firestore-contention.mjs`: twenty real Admin SDK transactions synchronize their first read,
  then each creates one unique item and increments one shared counter through SDK retries. The
  final item and counter totals must both be twenty.
- `listener-replacement.mjs`: the real client SDK with forced long polling unsubscribes from a
  query in its initial callback, immediately subscribes to the same query again, and verifies
  that the old listener receives no later snapshot while the replacement receives the initial
  and updated revisions exactly once. The same script can be run against Firebase CLI with
  `firebase emulators:exec --project demo-app --only firestore --config listener-replacement.firebase.json 'npm run smoke:listener-replacement'` from this directory. The harness supports Node.js 20 or newer and checks the runtime before opening a listener.
- `web/listener-lifecycle.html`: the browser Web SDK records one ledger across SSR-like initial
  markup, Auth readiness, overlapping user listeners, a project listener, a one-shot mail read,
  a destination query, route ownership replacement and one live write. It fails when a callback
  reaches an unsubscribed listener or more than one setting form is connected. Serve `web/` from
  a `fireemu exec --firebase-json tools/sdk-smoke/listener-lifecycle.firebase.json` child and open
  `listener-lifecycle.html?fs=<firestore port>&auth=<auth port>&project=demo-app`. The same file and
  rules run unchanged with the official Local Emulator Suite for differential checks.
- `web/index.html`: the browser build of the web SDK (WebChannel transport). Serve the
  directory (`python3 -m http.server 8765 --bind 127.0.0.1` in `web/`) from a `fireemu exec`
  child and open `http://127.0.0.1:8765/index.html?fs=<firestore port>&auth=<http port>&token=<FIREEMU_CONTROL_TOKEN>`; the page prints its checks as JSON. The variable is scoped to the child and is not printed by the daemon. `FIREEMU_TRACE_WEBCHANNEL=1` on the daemon traces the channel protocol.

```sh
# one-shot: fireemu exec --firestore-port 8080 --http-port 9099 --storage-port 9199 -- npm run smoke
cargo run -p fireemu -- up --firestore-port 8080 --http-port 9099 &
cd tools/sdk-smoke && npm install
export FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 GOOGLE_CLOUD_PROJECT=demo-app
npm run smoke        # firebase-admin
npm run smoke:client # firebase client SDK + rules
npm run smoke:lite   # Firestore Lite (REST) + rules

# App Check (needs the appCheck config and the functions codebase):
fireemu exec --config tools/sdk-smoke/fireemu.appcheck.json \
  --firestore-port 8080 --http-port 9099 --storage-port 9199 \
  --functions tools/sdk-smoke/functions-project --functions-port 5001 \
  -- sh -c 'cd tools/sdk-smoke && npm run smoke:appcheck'
```

Exit code 0 means every check passed; the JSON output lists each check. The App Check smoke uses the pinned `firebase-admin@14.3.0` Storage client to list the object uploaded by the Web SDK while Storage enforcement remains enabled.

`txn-order.mjs` probes transaction ordering with the web and Admin SDKs: a write before a read fails client-side with `Firestore transactions require all reads to be executed before all writes.` (the SDKs buffer writes until Commit, so the daemon, like production, never sees a misordered transaction), and a well-ordered transaction commits.

## `rules-unit-testing.mjs`

`@firebase/rules-unit-testing` (pinned at 5.0.2) against fireemu with **no explicit host
anywhere**: `initializeTestEnvironment({})` reads `GCLOUD_PROJECT` and `FIREBASE_EMULATOR_HUB`
out of the environment `fireemu exec` exported, asks the Emulator Hub `GET /emulators` for the
running services, and connects to what it answers. It then exercises the rules decisions,
`withSecurityRulesDisabled`, `clearFirestore`, and a write made while background triggers are
disabled -- asserting both that the trigger did not run and that re-enabling replays nothing.

```sh
./target/release/fireemu exec --config tools/sdk-smoke/fireemu.rules-unit-testing.json \
  --project demo-app --firestore-port 28180 --http-port 29199 --storage-port 29299 \
  --functions-port 25101 --ui-port 0 --hub-port 24400 \
  -- sh -c 'cd tools/sdk-smoke && node rules-unit-testing.mjs'
```

The script does nothing the official emulator does not require: `fireemu.rules-unit-testing.json`
selects the `firebase` compatibility profile (also the default), under which fireemu admits the
unsigned mock tokens `createMockUserToken` mints -- `iat: 0`, so `exp` is an hour after the
epoch, and a `sub` naming a user nobody created -- exactly as the official Firestore and
Storage emulators do. Running the same script under `"profile": "strict"` fails at the first
`authenticatedContext` call, which is the point of the two profiles.

## `rules-unit-testing-explicit-rules.mjs`

This focused smoke keeps Hub discovery but supplies explicit Firestore and Storage rule strings
to `initializeTestEnvironment()`. The real package installs them through Firestore's
`:securityRules` route and Storage's `/internal/setRules` route, then proves that both services
enforce owner-only access. The Storage checks use the valid bare worker-project bucket
`demo-app-w0`, proving that its mock token is bound to the routed project without registering a
session for it. It needs only Firestore and Storage:

```sh
./target/debug/fireemu exec --config tools/sdk-smoke/fireemu.rules-unit-testing.json \
  --project demo-app --only firestore,storage --firestore-port 0 --http-port 0 \
  --storage-port 0 --ui-port 0 --hub-port 24400 \
  -- sh -c 'cd tools/sdk-smoke && node rules-unit-testing-explicit-rules.mjs'
```

## Query completion and performance regressions

Install the locked dependencies with `npm ci` in this directory before comparing results. Check the installed `firebase-admin` and `@google-cloud/firestore` versions: a pre-existing `node_modules` directory can disagree with the manifest.

`npm run smoke:query-completion` seeds an isolated collection of 200 documents and checks exact IDs and values across internal-page boundaries, whole-query limits, offsets, descending field ordering, cursors, and read-only transactions. It independently reads the stored documents and deletes only its own fixture, including after a failed assertion. Use `fireemu exec` to own the daemon lifecycle:

```sh
fireemu exec --config tools/sdk-smoke/fireemu.smoke.json --only firestore --project demo-app -- npm --prefix tools/sdk-smoke run smoke:query-completion
```

`npm run smoke:large-query` seeds 65 documents with 192-KiB payloads and verifies exact full results above the 10-MiB transaction conflict-ledger boundary. It covers full and partial internal pages, repeated queries and batch reads in an explicit read-only transaction, and isolated fixture cleanup. Run it through the same `fireemu exec` lifecycle, replacing the script name with `smoke:large-query`. Read-only results must not acquire document conflict bookkeeping; execution-descriptor admission and snapshot retention remain bounded.

`npm run bench:firestore` requires a loopback `FIRESTORE_EMULATOR_HOST` and measures create, get, update, query, and uncontended transactions against a fresh local emulator. It uses 20 warmups per operation, 256-byte payload strings, reused SDK connections, and unique fixture collections. Each worker updates its own document. Seed writes, result assertions, and cleanup are outside the measured interval. Throughput includes the drain of all issued operations; transaction retries are counted separately from completed logical operations. Results contain every latency sample, p50/p95/p99, errors, and a semantic validation status. Accept a measurement only when the process exits successfully and every operation has `validation: "passed"`.

| Environment variable | Default | Purpose |
|---|---|---|
| `BENCH_ITERATIONS` | `200` | Measured operation count when duration is zero |
| `BENCH_CONCURRENCY` | `1` | Concurrent workers |
| `BENCH_DURATION_MS` | `0` | Positive values select a steady-state issue interval, followed by drain |
| `BENCH_QUERY_SIZE` | `33` | Exact query cardinality; zero selects an empty query |
| `BENCH_OPERATIONS` | `create,get,update,query,transaction` | Unique comma-separated operation names |

For example, set `BENCH_CONCURRENCY=32 BENCH_DURATION_MS=10000 BENCH_OPERATIONS=query` on the benchmark child for a sustained concurrent query run. Duration mode requires one operation per fresh daemon so growing create fixtures cannot affect later read comparisons. Run at least five paired comparisons, alternate backend order, retain raw JSON, and compare release builds on the same host with the same dependencies, settings, and fixtures. Measure the official emulator alongside the corrected query implementation instead of reusing historical targets derived from truncated queries. Keep Linux transport results separate from macOS results. Collect daemon CPU and memory externally; the driver retains responses until post-timing validation, so driver memory is a separate measurement scope. Growing create fixtures and deliberately contended transactions are distinct workloads from steady read comparisons.

`npm run smoke:index-merge` probes index merging and primary-key filters against the indexes in `conformance/firestore.indexes.json` (`mrg`: two composites ending in `star_rating ASC`; `pk`: wildcard `*` override with no single-field indexes). It records every outcome so fireemu and production can be compared line by line and asserts the documented cases (two composites merge, a missing third or a mismatched direction is rejected, an exempt field is rejected). Locally:

```sh
fireemu exec --config tools/sdk-smoke/fireemu.index-merge.json --firebase-json conformance/firebase.json --only firestore -- sh -c 'cd tools/sdk-smoke && GOOGLE_CLOUD_PROJECT=demo-app npm run smoke:index-merge'
```

Against production, set `PRODUCTION_ORACLE_PROJECT_ID=fireemu-35fe6` and `PRODUCTION_ORACLE_EXPECTED_PROJECT_NUMBER=592603257417` (the conformance indexes must be deployed to that project). Recorded on 2026-09-08: every `mrg` case and every `pk` case agreed between production and fireemu except the bare `orderBy(__name__, desc)` family, which production rejects without an explicit `__name__ DESC` index (already listed in `conformance/divergences.json` as an intentional local policy; the wildcard override and collection-group scope do not change that outcome).
