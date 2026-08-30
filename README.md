# fireemu

A deterministic, test-only local runtime for Firebase SDK and Functions code, written in Rust.

`fireemu` is not a faster re-implementation of the Firebase Emulator Suite. Its core is a
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

## Compatibility

fireemu is compatible with the listed Local Emulator Suite products as shipped by firebase-tools 15.28.2 -- Cloud Firestore, Firebase Authentication, Cloud Storage for Firebase, Cloud Functions and Cloud Pub/Sub, with Security Rules on the Firestore and Storage surfaces -- under the `firebase` compatibility profile and the evidence recorded in `spec/compatibility/contract.json`; it makes no complete-suite and no unqualified superset claim while Realtime Database, Firebase Hosting and App Hosting are deferred, Firebase Extensions is not planned, and the Emulator UI, the Emulator Hub, Logging, Eventarc, Cloud Tasks and Data Connect remain open gaps.

`spec/compatibility/contract.json` is that sentence in machine-readable form: it pins the baseline (`firebase-tools@15.28.2`, its lockfile integrity, its bundled emulator versions and the 2026-08-30 audit date), enumerates every emulator the pinned release ships, and binds each parity claim to the capability manifest entries it depends on and the tests and conformance fixtures that execute it. `cargo run -p compat-check` fails when the manifest, this README and the contract disagree; `docs/compatibility-contract.md` explains the rules.

| Product | Official emulator | Scope | State |
| --- | --- | --- | --- |
| Cloud Firestore | `firestore` | active | parity claimed |
| Firebase Authentication | `auth` | active | parity claimed |
| Cloud Storage for Firebase | `storage` | active | parity claimed |
| Cloud Functions for Firebase | `functions` | active | parity claimed |
| Emulator Suite UI | `ui` | active | open gap: fireemu serves its own UI, no workflow parity is claimed |
| Emulator Hub | `hub` | active | open gap: the discovery API on port 4400 is not served |
| Emulator logging | `logging` | active | open gap: the log stream on port 4500 is not served |
| Cloud Pub/Sub | `pubsub` | active | parity claimed for the documented gRPC subset |
| Eventarc | `eventarc` | active | open gap |
| Cloud Tasks | `tasks` | active | open gap |
| Firebase Data Connect | `dataconnect` | active | open gap |
| Firebase App Check | -- | active | a fireemu addition; the official suite ships no App Check surface |
| fireemu control API | -- | active | a fireemu addition; sessions, virtual clock, snapshots, fault plans |
| Firebase Realtime Database | `database` | deferred | nothing is served; low expected near-term demand |
| Firebase Hosting | `hosting` | deferred | nothing is served; low expected near-term demand |
| App Hosting | `apphosting` | deferred | nothing is served; low expected near-term demand |
| Firebase Extensions | `extensions` | not planned | the managed service is deprecated and shuts down on 2027-03-31 |

### Compatibility profiles

fireemu is deliberately stricter than the official emulators in places. The contract separates the two so that extra strictness can never be read as parity, and the top-level `profile` key of `fireemu.json` selects one:

```json
{ "schemaVersion": 1, "profile": "firebase", "firestore": { "edition": "standard", "apiMode": "native" } }
```

- **`firebase`** (the default) reproduces what the pinned suite ships and Firebase documents, including its documented limitations. Nothing in this profile may refuse a request the official emulator admits.
- **`strict`** adds fireemu's own validation on top. Every key here may only refuse more than the official emulator, and every refusal it adds is published as a capability precision or as a documented divergence in `conformance/divergences.json`.

The daemon derives three settings from the profile, and any explicit key wins over its default:

| Setting | `firebase` | `strict` |
| --- | --- | --- |
| `firestore.indexValidationPolicy` | `emulator`: a query whose composite index is not configured runs as if it existed, with an `FS_EMULATOR_INDEX_ASSUMED` warning naming the index production would need. The pinned official Firestore emulator does not check indexes at all. | `conservative`: the query is refused with `FAILED_PRECONDITION` and the `firestore.indexes.json` fragment, before it runs. |
| `firestore.enforceLimits` | `false`: a Standard query limit violation is reported as an `FS_LIMIT_OBSERVED:<limit id>` warning and the query runs. | `true`: the query is refused with `INVALID_ARGUMENT` and the violated limit. |
| ID tokens on the Firestore and Storage Rules surfaces | the unsigned mock tokens the official emulators admit are admitted: `request.auth` is built from the claims as given, so a `sub` naming no user and an `exp` nobody reads are both fine (this is what makes `@firebase/rules-unit-testing` work unchanged). | the full verification stands: issuer, audience, expiry on the virtual clock, a subject that names a user of the project's Auth store, and revocation. |

Two checks stay on in **both** profiles, and the contract records them as deliberate divergences of the `firebase` profile because the official emulators do not make them: a token's audience must name the project, so a token can never cross a session or project boundary, and a token that claims to be signed must verify against the session key, so a forged `RS256` token never becomes an identity. Set `firestore.indexValidationPolicy: "firebase"` explicitly for a run whose oracle is the Firebase *backend* — which refuses the unindexed query — rather than the emulator.

`fireemu capabilities` and `GET /v1/capabilities` publish the active profile, and the start banner prints it. The contract lists under each profile's `sets` exactly the keys the daemon derives from it, and a unit test fails when the two drift; every other key a profile names (`limits.enforcement`, `limits.quotaAccounting`, `limits.warningsAsErrors`, `rules.staticLimitChecks`, `rules.runtimeBudgets`, `auth.idTokenSigning`, `appCheck.enabled`, `events.delivery`, `scheduler.clock`, `projects.requireDemoPrefix`) is `declared` with a status saying whether the loader reads it by hand or does not implement the value at all, so a profile value that is a statement of intent is never mistaken for a switch. `compat-check` checks every key and value both profiles name against `spec/config/fireemu.schema.json`, and that the two profile names are exactly the values that schema's `profile` key accepts.

## Status

Implemented: Milestone A (verification-ready core), Milestone B (strict Firestore gateway: query / index / limit validation), Milestone D core (`ST-OBJ-1`: Cloud Storage objects with generations, listing, resumable uploads on both the Firebase and the JSON API protocols; Storage Security Rules evaluated at upload finalization against the received bytes), Milestone E (local Firestore execution: versioned documents, atomic commits with preconditions / masks / transforms, MVCC transactions with read-set and query re-validation, queries, aggregations, `Write` and `Listen` streams), `FS-REST-1` (the Firestore REST API on the same port as gRPC), Milestone H0 (Auth over the Identity Toolkit REST surface: password / anonymous / custom token / email link / phone / fixture identity provider sign-in, email actions with codes readable from `/emulator/v1/projects/{p}/oobCodes`, TOTP and phone second factors, the Admin SDK account, import, bulk-delete and session-cookie routes, the emulator config route; see "Authentication") native Security Rules enforcement on every Firestore surface (`Bearer owner` bypass, ID tokens verified against the Auth store, reads checked against the returned snapshot, writes checked inside the commit, queries proven from their constraints; see `RULES-QUERY-CONSTRAINTS` in `crates/fireemu-adapter-grpc/src/rules.rs`), and Milestone C (Cloud Functions: a `firebase-functions` v2 codebase runs in the bundled Node runner; Firestore document triggers, Storage object triggers, `onSchedule` driven by the virtual clock, `onRequest` / `onCall` over an HTTP port, retries with virtual-time backoff, `await-idle`).

The real `firebase-admin`, `firebase` (Node: gRPC streams; browser: the WebChannel transport on the same port), and `firebase/firestore/lite` (REST) SDKs run against the daemon; `tools/sdk-smoke` holds the smoke scripts and a browser page. Rules cover `get()` / `exists()` / `getAfter()`, the `string` / `list` / `map` / `set` / `path` / `timestamp` / `duration` / `latlng` / `math` / `hashing` surfaces, `map.diff()` and its key sets, range indexing, `path.bind()`, query proofs from equality / `in` / `!=` / `not-in` / array / range constraints and `request.query`, and `firestore.get()` in Storage rules. `Listen` resumes from a token or read time by replaying only the changes since (MVCC history), and `PartitionQuery` splits collection groups for parallel readers. A target whose own query is refused (a missing composite index, a malformed query) is removed with its cause -- `TargetChange REMOVE` carrying `FAILED_PRECONDITION` and the actionable index diagnostic -- on both gRPC and WebChannel, and the stream stays open for its other targets; a stream-level error is reserved for session-wide or database-wide failures. `ExecutePipeline` is validation-only (`FS-PIPE-RPC-1`): a pipeline is decoded, identified and checked against the documented stage registry, and a well-formed one is then answered `UNIMPLEMENTED FS_PIPE_VALIDATION_ONLY` rather than executed. Storage object versioning, signed URLs and compose are not served.

## Install

```sh
npm install -D fireemu
npx fireemu doctor
```

```sh
pnpm add -D fireemu          # or, without adding a dependency: pnpm dlx fireemu doctor
yarn add -D fireemu
```

`fireemu` on npm is a small Node launcher; the daemon for your platform arrives as an optional
dependency (`@fireemu/darwin-arm64` and its siblings), each declaring the `os` and `cpu` it is for,
so exactly one binary is installed and the rest are skipped. There is no install script and nothing
is downloaded at install time, so an install that resolved from a cache or a private registry is a
complete, offline installation. The Emulator UI is compiled into the binary; the Node runner that
hosts a Functions codebase ships beside it.

### Supported platforms and prerequisites

| Package | OS | Arch | Rust target |
| --- | --- | --- | --- |
| `@fireemu/darwin-arm64` | macOS 13+ | Apple silicon | `aarch64-apple-darwin` |
| `@fireemu/darwin-x64` | macOS 13+ | Intel | `x86_64-apple-darwin` |
| `@fireemu/linux-x64` | Linux, any libc | x86-64 | `x86_64-unknown-linux-musl` (static) |
| `@fireemu/linux-arm64` | Linux, any libc | arm64 | `aarch64-unknown-linux-musl` (static) |
| `@fireemu/win32-x64` | Windows 10+ | x86-64 | `x86_64-pc-windows-msvc` |

The Linux builds are statically linked against musl, so they run on any distribution and inside
distroless and Alpine containers; the cost is musl's slower allocator, which a loopback daemon
driven by test suites can afford.

| Runtime | Needed for | Version |
| --- | --- | --- |
| Node | the npm launcher, and `--functions <dir>` | 20 or newer |
| `firebase-functions` (in your codebase) | `--functions <dir>` | v6 or v7 |
| Java | nothing | **not required** -- `fireemu` runs no JVM emulator |

Firestore, Auth, Storage, Security Rules and the Emulator UI are served by the binary itself and
need no runtime at all. `npx fireemu doctor` reports the installed version and platform, whether
the UI is compiled in, where the Node runner was found and which `firebase-functions` majors it
instruments, the Node version, and that no JVM is needed; anything missing comes with a remediation
line, and a broken installation exits non-zero so a setup script can gate on it. The report carries
versions and paths only -- never tokens, keys or configuration contents.

### Upgrade, uninstall, offline

- **Upgrade**: `npm install -D fireemu@<version>`. The launcher pins its platform packages to its
  own exact version, so `fireemu@1.2.3` can only resolve `@fireemu/linux-x64@1.2.3`; the launcher
  and the binary always move together.
- **Uninstall**: `npm uninstall fireemu`. Nothing is installed outside `node_modules`: no cache
  directory, no global binary, no downloaded component.
- **Offline**: `npm install --offline` works once the tarballs are in the npm cache, as does a
  private registry mirroring `fireemu` and the `@fireemu` scope. Vendor them with `npm pack`.
- **A vendored or self-built binary**: point `FIREEMU_BINARY_PATH` at it and the launcher runs that
  instead of resolving a platform package.
- **No binary for your platform**: the launcher prints what the host is, which platforms were
  published, and the three install flags that usually cause an optional dependency to be skipped
  (`--omit=optional`, `--no-optional`, a lockfile built on another platform).

Release archives with SHA-256 sums are attached to each GitHub Release for users who do not want
npm; they are the same trees as the npm packages. Two software bills of materials sit beside
them, both in `SHA256SUMS`: `fireemu-<version>.cargo.cdx.json`, the daemon's Rust dependency
graph with licences (CycloneDX, from `Cargo.lock`), and `fireemu-<version>.npm.cdx.json`, the npm
tree of an installation. Every build uses the compiler `rust-toolchain.toml` pins, with the
checkout and cargo-home paths remapped to fixed names, and the release workflow builds linux-x64
twice under different directories and reports whether the bytes agree; the Linux archives are
written with a fixed member order, owner and mtime. Before publishing, the release installs the
packed linux-x64 packages offline into a project (a path with a space and non-ASCII characters,
through a symlink, from a read-only directory) and replays the conformance corpus against that
installed binary rather than the workspace build; `node npm/scripts/pack-local.mjs && node
npm/scripts/verify-install.mjs --dist npm/dist` runs the same installation proof on a developer
machine and in CI. `npm/` holds the launcher, the platform-package generator and the release
scripts.

## Run

```sh
cargo run -p fireemu -- up --firestore-port 8080 --http-port 9099 --storage-port 9199
#   optional: --config fireemu.json  (see spec/config/fireemu.schema.json)
#   optional: --config firebase.json  (a file without `schemaVersion` is a firebase.json)
#   optional: --functions ./functions --functions-port 5001   (a firebase-functions v2 codebase)
#   optional: --firebase-json firebase.json --project my-app   (rules, indexes, ports from a Firebase project)
#   optional: --hub-port 4400   (the Emulator Hub; 0 turns it off)
```

`fireemu exec` is the `firebase emulators:exec` equivalent: it serves the same, runs a command once every listener is bound, stops everything when the command exits and exits with its status. `emulators:start` and `emulators:exec` are exact aliases of `up` and `exec`, so an existing script keeps its command name.

```sh
fireemu exec --config firebase.json --project my-app --only auth,firestore,storage -- vitest run
```

SIGINT and SIGTERM are forwarded to the command (its status becomes `128 + signal`) and nothing is left listening or running.

### Command surface

| command | what it does |
| --- | --- |
| `up`, `emulators:start` | serve until Ctrl-C |
| `exec`, `emulators:exec` | serve, run `-- <command...>`, exit with its status |
| `emulators:export <dir>` | write an export directory from a running suite (see [Import and export](#import-and-export)) |
| `doctor`, `capabilities` | versions and catalogs; the Capability Manifest |

Flags, in the official spellings: `--only`, `--project` / `-P`, `--config`, `--import`, `--export-on-exit`, `--inspect-functions [port]` and `--log-verbosity quiet|info|debug`, next to fireemu's `--firebase-json`, `--firestore-port`, `--http-port`, `--storage-port`, `--functions-port`, `--pubsub-port`, `--functions`, `--ui-port` and `--hub-port`. `--inspect-functions` inserts Node's `--inspect=<port>` (default 9229) before the runner script; a configured `functions.runner` that is not Node is refused rather than started without the inspector.

Exit codes: the command's own status from `exec`, `128 + signal` when a signal ended it, `1` for a startup failure or a refused configuration, `2` for a usage error. A refusal never binds a listener and never runs the command.

### `--only` decides what runs

`--only` is a lifecycle switch, not only an environment one: a service it leaves out binds **no listener at all**, so its port stays free and no client can reach a product this run is not serving. Selecting an official service fireemu does not serve fails immediately with the reason:

```text
error: --only: "database" is an official Local Emulator Suite service that fireemu does not serve
       (deferred: the Realtime Database emulator is not in the active supported surface);
       fireemu serves auth, firestore, storage, functions, pubsub, appcheck
```

`--only functions:<codebase>` picks one codebase out of a multi-codebase `firebase.json`, as the official CLI spells it.

The one shared socket is the Identity Toolkit's: it also carries the control API, the App Check exchange and the Emulator UI's API. When `auth` is not selected the control plane moves to an ephemeral loopback port (printed in the banner, exported as `FIREEMU_CONTROL_URL`) and the configured Auth port is left free.

### Environment the command receives

Names and formats follow the pinned `firebase-tools@15.28.2` `src/emulator/env.ts`.

| variable | when | format |
| --- | --- | --- |
| `FIRESTORE_EMULATOR_HOST` | `firestore` selected | `host:port` |
| `FIREBASE_FIRESTORE_EMULATOR_ADDRESS` | `firestore` selected | `host:port` |
| `FIREBASE_AUTH_EMULATOR_HOST` | `auth` selected | `host:port` |
| `FIREBASE_STORAGE_EMULATOR_HOST` | `storage` selected | `host:port` |
| `STORAGE_EMULATOR_HOST` | `storage` selected | `http://host:port` |
| `FIREBASE_EMULATOR_HUB` | the Hub is bound | `host:port` |
| `FIREEMU_FUNCTIONS_HOST` | a codebase is loaded | `host:port` |
| `CLOUD_EVENTARC_EMULATOR_HOST` | a codebase is loaded | `http://host:port` (the functions port; it serves `publishEvents`) |
| `CLOUD_TASKS_EMULATOR_HOST` | a codebase is loaded | `host:port` (the functions port; it serves the queue routes) |
| `PUBSUB_EMULATOR_HOST` | `pubsub` selected | `host:port` (the Pub/Sub gRPC port) |
| `FIREEMU_APP_CHECK_EMULATOR_HOST`, `FIREEMU_APP_CHECK_JWKS_URL` | App Check active | `host:port`, URL |
| `FIREEMU_CONTROL_TOKEN`, `FIREEMU_CONTROL_URL` | always | token, URL |
| `GCLOUD_PROJECT`, `GOOGLE_CLOUD_PROJECT`, `FIREBASE_CONFIG` | always | project ID, project ID, JSON |

There is no `CLOUD_STORAGE_EMULATOR_HOST` variable: the `firebase-tools` constant of that name emits `STORAGE_EMULATOR_HOST`, which is the one above. `FIREBASE_DATABASE_EMULATOR_HOST` is never set, because Realtime Database is a deferred product fireemu does not serve.

Two deliberate differences from the official CLI, both published in the Capability Manifest under `CLI-02`:

- fireemu also sets `GOOGLE_CLOUD_PROJECT` (the official CLI sets only `GCLOUD_PROJECT`), because the Google client libraries read either one;
- fireemu **removes** the variables of unselected services from the command's environment. The official CLI only adds, so a stale `FIRESTORE_EMULATOR_HOST` in your shell survives `--only auth` and silently points the suite at whatever used to run there.

### Emulator Hub

The Hub is the discovery surface official tooling looks for. It listens on the official default port 4400 (`emulators.hub`, `--hub-port`, `daemon.hubPort`), best effort like the UI port: a busy default only disables discovery, while a port asked for explicitly must be free. `--hub-port 0` turns it off.

```text
GET  /                                       the locator plus this listener's host and port
GET  /emulators                              every running emulator, keyed by name
PUT  /functions/disableBackgroundTriggers    {"enabled": false}
PUT  /functions/enableBackgroundTriggers     {"enabled": true}
```

Each `/emulators` entry carries `name`, `host`, `port`, `pid` and its `listen` specs, and only services that actually bound a listener appear. The Hub also writes `hub-<project>.json` into the OS temp directory at start (`{"version", "origins", "pid"}`) and removes it at exit, so `@firebase/rules-unit-testing` and the Firebase CLI find a running suite the way they always do:

```js
// no projectId, no host, no port: everything comes from the hub
const env = await initializeTestEnvironment({});
```

`tools/sdk-smoke/rules-unit-testing.mjs` is that script end to end, and it runs unmodified: under the default `firebase` profile a suite moving from the official emulator changes nothing. `authenticatedContext("alice")` mints the token `@firebase/util`'s `createMockUserToken` produces — unsigned, `iat: 0` so `exp` is an hour after the epoch, and a `sub` naming a user the Auth emulator has never seen — and fireemu builds `request.auth` from it exactly as the official Firestore and Storage emulators do. Under `strict` the same token is refused, because there the subject must name a user of the project's Auth store and the expiry must hold on the virtual clock.

**Background triggers.** Disabling them **drops** the Firestore, Storage, Pub/Sub and Auth events that arrive while they are off; nothing is held and nothing is replayed when they come back. That is what the official emulator does (its background-trigger route answers `204` and discards the body), and it is the property the switch exists for: seeding data must not fire the triggers a later assertion depends on. HTTP and callable invocations, manual `functions/{name}:run` requests and virtual-clock schedule runs keep working throughout, and events already accepted are still delivered and retried.

The Logging emulator stream (the official port 4500) is **out of scope for this release**; an `emulators.logging` entry is reported and nothing is served on that port. The functions log stream the UI consumes lives on the control API instead.

### `firebase.json` and `.firebaserc`

`--firebase-json` (or `--config` with a file that has no `schemaVersion`) reads the sections fireemu can honour, relative to that file's directory:

- **`firestore`** in object or array (named-database) form: `rules` and `indexes` (the legacy `index` spelling too) of the `(default)` database;
- **`storage`** in object or array form: the `rules` of the entry without a `target`;
- **`functions`** in object or array (multi-codebase) form: `source`, `codebase`, `runtime`, `ignore`;
- **`emulators.<name>.host` / `.port`** for `firestore`, `auth`, `storage`, `functions`, `hub` and `ui`, plus `emulators.ui.enabled` and `emulators.singleProjectMode`. Only loopback hosts are accepted (`127.0.0.1`, `localhost`, `::1`), and this is a documented divergence from the official CLI, which binds `0.0.0.0`, `::` or a LAN address as given: the daemon serves without a credential on loopback and has no routable mode, so such a host exits 1 naming the key. A suite that must be reached from another machine belongs behind a reverse proxy that adds the credential.

`--project` resolves through `.firebaserc`: a defined alias becomes its project ID, no `--project` uses the `default` alias, and a value that is not an alias is taken as a project ID — exactly what `firebase --project` does. Ports given on the command line override `firebase.json`, which overrides the canonical configuration.

Nothing is silently dropped. An `emulators.<name>` entry for a product fireemu does not serve is an **error** when `--only` named that product and a **notice** otherwise; anything fireemu applies only in part says so on stderr:

```text
note: firebase.json: firestore[1]: the named Firestore database reports is served, but its own
      rules and indexes are not loaded; only the (default) database's are
```

Applied in part, and reported each time: a named Firestore database's own rules and indexes (only `(default)`'s are loaded), a per-target Storage ruleset (one ruleset covers every bucket), and a second Functions codebase — fireemu runs one runner, so a multi-codebase project names its codebase with `--only functions:<codebase>`. `emulators.singleProjectMode` is recorded and published rather than enforced separately: fireemu already isolates every project into its own session, which is stricter.

The subset is written down in `spec/config/firebase-json.schema.json`, with a valid and an invalid corpus under `spec/config/firebase-json-examples/` and `spec/config/firebase-json-invalid-examples/` that `cargo run -p config-schema-check` validates and a unit test replays through the loader itself.

The daemon prints the environment variables SDKs need (`FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST`, `FIREBASE_STORAGE_EMULATOR_HOST` / `STORAGE_EMULATOR_HOST`). Storage rules load from `storage.rules` in the config or `PUT /v1/storage/rules`. Security Rules come from `rules.source` in the config file or at runtime:

```sh
curl -X PUT http://127.0.0.1:9099/v1/rules -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s firestore.rules '{source: $s}')"
# or the emulator's own route, on the Firestore port, which is what a test environment calls
curl -X PUT http://127.0.0.1:8080/emulator/v1/projects/demo-app:securityRules \
  -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s firestore.rules '{rules: {files: [{name: "firestore.rules", content: $s}]}}')"
curl http://127.0.0.1:8080/emulator/v1/projects/demo-app:ruleCoverage      # the report
open http://127.0.0.1:8080/emulator/v1/projects/demo-app:ruleCoverage.html # the same, as a page
curl -H "Authorization: Bearer $FIREEMU_CONTROL_TOKEN" \
  http://127.0.0.1:9099/v1/sessions/default/rules/requests                 # the last decisions
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 60}'
curl -X POST http://127.0.0.1:9099/v1/sessions/default/reset   # drop Firestore + Auth state
curl -X POST http://127.0.0.1:9099/v1/sessions/default/snapshots -d '{"name": "seeded"}'          # capture everything
curl -X POST http://127.0.0.1:9099/v1/sessions/default/snapshots/seeded:restore                  # put it back, atomically
curl -X PUT  http://127.0.0.1:9099/v1/sessions/default/faultPlan -d '{"rules": [{"match": {"operation": "firestore.commit", "nth": 2}, "action": {"type": "returnError", "code": "ABORTED"}}]}'
```

Sessions are isolated by project: `POST /v1/sessions -d '{"project": "demo-b", "buckets": ["extra-bucket"], "apiKeys": ["key-b"]}'` gives `demo-b` its own Firestore databases, Storage buckets (its `demo-b.appspot.com` / `demo-b.firebasestorage.app` plus the ones it declares), Auth store, fault plan, snapshots and text indexes. Admin SDK routes under `projects/demo-b/...` use its store; client SDK routes reach it through a declared API key (`?key=key-b`), the audience of the ID token they carry, or the refresh token they present. ID tokens are accepted only by the project of their audience (a `demo-b` token on `demo-app` data or buckets is `UNAUTHENTICATED`, as in production). `POST /v1/sessions/demo-b/reset` wipes only that project, `DELETE /v1/sessions/demo-b` removes it, and a reset of `default` wipes everything except the registered sessions; the clock, rules and functions are shared by every session. A reset and a deletion are all or nothing: every store they will write is checked first, and one that refuses answers `INTERNAL` with the store named while the session keeps its data, its registration and its snapshots.

Snapshots copy what the session owns (its Firestore databases, Storage objects, Auth users, fault plan and text indexes) and, for the default session, the shared parts (the clock, both rulesets, the auto-ID generator) in one exclusive section (a restore of the default session is a new epoch: streams end, the functions runtime resets; outstanding functions work is not captured); they live in memory. A capture is all or nothing too: every part is copied before any of it is retained, so a store that cannot be read refuses the snapshot instead of retaining an empty part. A restore validates every part, takes a pre-image of every store and only then applies them in order; a store that refuses the apply is reported and the stores already written are put back, so the session is never half of one snapshot and half of another. Each session retains at most 16 named snapshots: a seventeenth name is `RESOURCE_EXHAUSTED` (429) and changes nothing, while capturing over a name the session already holds is always admitted and releases the copy it held. What a snapshot retains is the visible state, not the running session: the Firestore part holds the newest version of every live document -- none of the MVCC history, open transactions or tombstones, so a `read_time` or resume token from before the restored state is refused exactly as after a compaction -- and the Storage part shares each object's bytes with the live store by reference, so capturing the same objects again, or restoring them, costs no copy of the data; only an overwrite allocates. The Auth part still copies its store eagerly. `GET /v1/sessions/{s}/snapshots` reports `retained`, `limit` and `remaining`. Fault plans (spec 18) name an operation (`firestore.commit` / `read` / `beginTransaction`, `storage.upload` / `read` / `delete` / `list`, `functions.invoke` / `deliver`; a rule with only an `eventType` is a `functions.deliver` rule), optionally the nth occurrence (counted per function when one is named) and a function, and an action that applies to that operation (`returnError` with a gRPC name or HTTP code, `delay` seconds, `duplicate` count, `crashRunner`, `timeout`, `deadLetter`, `transactionConflict`, `dropConnection`); a combination the adapters would ignore is refused. `functions.invoke` rules also apply to HTTP invocations and to scheduled or manual runs; a `delay` holds an event until the virtual clock reaches the instant and then applies the other actions of the rule set. `dropConnection` closes the connection (or resets the gRPC stream) instead of answering on the Firestore, Storage and functions ports; over WebChannel it is reported as `UNAVAILABLE`, and for event invocations it is a failed attempt. `GET .../faultPlan` shows what fired.

The Rules language itself is measured rather than assumed. `conformance/src/rules-probe` installs the same bounded Rules programs into the pinned official Firestore emulator and into fireemu -- through the same `PUT /emulator/v1/projects/{project}:securityRules` route on both sides -- and compares the verdict of each one: 680 language claims (260 of them generated from a seed, with a mismatch shrunk to its smallest disagreeing form) in `conformance/rules-matrix.json`, and 22 whole-program probes for budgets, runtime errors, the call-graph limits and query authorization in `conformance/rules-programs.json`. `pnpm -C conformance run matrix` re-records against the official runtime and `run matrix:check` replays fireemu and fails on drift; `run programs` and `run programs:check` do the same for the programs. Three rows are documented divergences, all the same one: the official compiler's static type checker rejects at load what fireemu raises at evaluation, and the request decision is the same.

Evaluation is observable the way the official emulator makes it observable. `GET /emulator/v1/projects/{project}:ruleCoverage` on the Firestore port answers the loaded rules files and a report of one tree per `allow` condition and per function body, each node naming its `line`, `column`, `currentOffset` and `endOffset` and the values it took with a count each; an expression that raised is an `undefined` value carrying the innermost expression that raised, and one nothing reached has children and no values. `:ruleCoverage.html` serves the same document as a page that underlines every evaluated expression. fireemu adds `GET /v1/sessions/{s}/rules/requests` on the control API: the last 100 decided requests, newest first, with what every expression evaluated to while each was decided -- behind the control token, and carrying no token, no signature and no claim other than the subject the rule saw as `request.auth.uid`. All three drop what they hold when another ruleset is loaded, because every position they name is an offset into the source that has just been replaced.

Without rules every request is allowed (the daemon says so at start). `fireemu doctor` prints versions and catalogs; `fireemu capabilities` prints the Capability Manifest.

### Emulator UI

The daemon serves an Emulator UI on `--ui-port` (default 4000, best effort: a busy port only disables it; `--ui-port 0` turns it off) at `http://127.0.0.1:4000/ui`: an overview, a Firestore data browser with a typed field editor and live updates, Auth users with custom claims / second factors / pending action codes, Storage objects, Functions (registered triggers, invocation history, a live log stream, manual schedule runs and Pub/Sub publishes), both rulesets with the requests Security Rules decided and their per-expression traces, App Check (the configured apps, the baseline modes, debug tokens and the observation counters), and the runtime controls (virtual clock, snapshots, fault plans, sessions). Its API under `/ui/api/` is a same-origin, privileged front to the existing surfaces (Firestore REST as owner, the Identity Toolkit admin routes, the Storage JSON API, the App Check debug-token routes, the control API); every request to it must present the control token in `Authorization: Bearer` (the served page carries it; a query parameter is not accepted), the listener answers only to loopback `Host`s, the page ships a Content Security Policy that keeps it out of other sites' frames, object downloads through the front are always attachments, and at most 64 event streams are open at once. Functions and Pub/Sub routes belong to the default session; the Storage page lists the selected session's buckets.

The App Check page shows this instance's JWKS `kid` and token TTL, the effective baseline mode of every service, the apps registered for the selected session's project with their configured digest count against their dynamic registrations, the debug tokens of one app, and the counters and recent observations of the session. Registering a debug token returns the raw secret exactly once: the page shows it in a copyable field behind a warning and drops it when it is dismissed or the page is left. It is never stored in the browser, never put in a URL, and never appears in a list, in `window.__FIREEMU__` or in an observation — the daemon keeps only its SHA-256 digest and cannot show it again. A runtime with `appCheck.enabled` false says so on the page instead of offering the surface.

The app lives in `ui/` (Solid, Vite, Tailwind) and is embedded into the binary at compile time; a binary built without it serves a placeholder page that says so:

```sh
pnpm -C ui install && pnpm -C ui build     # writes ui/dist (not committed)
cargo build --release -p fireemu    # embeds it
pnpm -C ui test && pnpm -C ui e2e          # unit tests; Playwright against a real daemon
```

### Composite indexes

`firestore.indexValidationPolicy` decides what happens to a query whose composite index is not in `firestore.indexFile`. The compatibility profile sets its default (`emulator` under `firebase`, `conservative` under `strict`); naming the key overrides that:

- `emulator`: the query runs as if the index existed, which is what the Firebase Emulator Suite does; the gateway records an `FS_EMULATOR_INDEX_ASSUMED` warning naming the index production would need. It says nothing about production index conformance.
- `conservative` and `firebase`: the query is refused with `FAILED_PRECONDITION` and the `firestore.indexes.json` fragment, before it runs. `firebase` is the Firebase backend's behaviour; `conservative` never accepts a query without a proven supporting index.

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

### Authentication

The Identity Toolkit surface reproduces what the pinned official Auth emulator serves, measured route by route by the conformance suite (`auth/*` fixtures) rather than assumed: the client routes (`accounts:signUp` including the upgrade of an anonymous session with an `idToken`, `signInWithPassword`, `signInWithCustomToken` with the Admin SDK's unsigned JWT or a strict-JSON fake token, `lookup`, `update`, `delete`, the email-action routes, phone sign-in, `signInWithIdp` with a fixture assertion, `createAuthUri`, the fixed `/v1/projects` and `/v1/recaptchaParams` documents), the Admin routes real projects use (`projects/{p}/accounts` create, `lookup`, `update`, `delete`, `batchGet`, `batchCreate`, `batchDelete`, `query`, `sendOobCode` link generators and `projects/{p}:createSessionCookie`), the multi-factor routes, `securetoken`, and the emulator-only routes (`/emulator/v1/projects/{p}/oobCodes`, `verificationCodes`, `accounts` for a wipe, and `config` to read or `PATCH` the project switches). Every route is one row of a single table (`crates/fireemu-adapter-http/src/identity_toolkit/routes.rs`) that also decides its privilege class and its bounded App Check operation label; a path the table does not describe is the official `Not Found` envelope, a known path with another method is `405`.

Error shapes follow the official emulator, including its documented differences from production: by default a password sign-in distinguishes `EMAIL_NOT_FOUND` from `INVALID_PASSWORD` and a password reset for an unknown address is `EMAIL_NOT_FOUND`, while `PATCH /emulator/v1/projects/{p}/config` with `{"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}` collapses both into `INVALID_LOGIN_CREDENTIALS`, answers the reset silently and hides `createAuthUri`'s sign-in methods. `signIn.allowDuplicateEmails` is recorded and exported but does not admit duplicate accounts yet. Phone second-factor enrollment refuses an anonymous, phone, custom-token or Game Center first factor (`UNSUPPORTED_FIRST_FACTOR`), an unverified email (`UNVERIFIED_EMAIL`) and a number already enrolled (`SECOND_FACTOR_EXISTS`) without creating or consuming a verification code; the pending-credential response obfuscates the number to its last four digits. TOTP factors (`AUTH-MFA-TOTP-1`) are a fireemu addition the official emulator has no route for, so the verified-email requirement is not inferred for them.

Two behaviours are deliberately stricter than the official emulator and are recorded as divergences of the `firebase` profile in `spec/compatibility/contract.json`: transient credentials are bounded (email action codes expire after an hour and phone codes after ten minutes of virtual time, pending second-factor sign-ins after an hour, a TOTP enrollment session answers `SESSION_EXPIRED` for one further session lifetime and is then reaped, and each kind refuses with `QUOTA_EXCEEDED` past 1000 outstanding codes per project or 32 pending sessions per user, where the official emulator keeps every code until it is consumed and its pending credential is stateless), and a privileged revocation (`revokeRefreshTokens`), a disablement or a privileged credential change end every session by invalidating the user's refresh tokens, where the official emulator lets an old refresh token keep minting. A self-service password or email change through the session's own ID token moves `validSince` and keeps that session, as the official emulator does, so the client SDK's `updatePassword` / `updateEmail` keep the user signed in even on a pinned clock. Refresh tokens are never swept by the transient-credential policy.

Default session snapshots carry no TOTP shared secret (`INV-AUTH-003`, ADR-034): an enrolled factor is captured with a detached secret and rebound on restore to the secret the live store still holds; a factor withdrawn between capture and restore is dropped from the restored account and reported on stderr, never restored unusable. `TotpSecret` zeroes its buffer when dropped.

### App Check

`appCheck` is off by default. Enabling it turns on the local App Check issuer — the daemon registers Firebase app IDs from configuration, exchanges a registered debug secret for a locally signed RS256 token, and publishes the public key at a local JWKS endpoint — and lets `appCheck.services` enforce that token on Firebase Authentication, Cloud Firestore and Cloud Storage, while callable Functions enforce it per function. This is milestones AC0 to AC3 of [docs/specifications/firebase-app-check.md](docs/specifications/firebase-app-check.md): `APPCHECK-CORE-1`, `APPCHECK-DEBUG-EXCHANGE-1`, `APPCHECK-JWKS-1`, `APPCHECK-ENFORCE-1`, `APPCHECK-FUNCTIONS-1`, `APPCHECK-OBSERVE-1` and `APPCHECK-SDK-WEB-1`.

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
     -H "authorization: Bearer $FIREEMU_CONTROL_TOKEN" -H 'content-type: application/json' \
     -d '{"displayName": "ci runner", "generate": true}'
# -> the raw secret exactly once; a later list shows only the id, name, creation time and digest prefix
```

The signing key is a dedicated 2048-bit RSA key drawn from the operating system CSPRNG once per daemon instance (`instance-rsa`); its `kid` starts with `fireemu-app-check-` and it is never the Auth session key. Two normally started daemons therefore reject each other's tokens, and a restart invalidates the previous instance's JWKS. Tokens carry the production claim shape (`iss`, `sub`, both `projects/{projectNumber}` and `projects/{projectId}` audiences, `iat`, `exp`, `jti`) plus a local private `fireemu_epoch` claim that binds a token to the project session epoch. Expiry is decided on the virtual clock: `iat <= now < exp`, with `now == exp` already expired.

`--only appcheck` selects the service, and `fireemu exec` then exports `FIREEMU_APP_CHECK_EMULATOR_HOST=host:port` and `FIREEMU_APP_CHECK_JWKS_URL=http://host:port/v1/jwks`. Selecting `functions` selects App Check implicitly when it is enabled. No raw debug secret is ever generated or exported implicitly.

**Enforcement.** `appCheck.services.{auth,firestore,storage}` is `off`, `unenforced` or `enforced`. `off` does no token work at all — the header is never even read. `unenforced` classifies and records every request but denies none, and a missing or invalid token never becomes an app identity. `enforced` admits only a verified token or an explicit privileged bypass; a client sends the token as `X-Firebase-AppCheck`, exactly once. Firestore covers unary gRPC, REST, the `Write` and `Listen` streams and the browser WebChannel transport; Storage covers resumable uploads as well as everything else.

**Long-lived operations.** A stream, a channel and an upload session all outlive the request that created them, so each is admitted once and keeps that admission:

| Operation | Admitted | Kept for | A later request |
|---|---|---|---|
| `Write` / `Listen` gRPC stream | opening metadata, classified once; decided as soon as the first request names the database | the stream's whole life | is not re-decided; token expiry and a policy change do not end an admitted stream. Reconnecting is a new admission |
| WebChannel | the opening init header block (`headers=` / `$httpHeaders`), plus a real HTTP field if one is sent | the channel's life; the channel is bound to the admitted app and the session epoch of that admission | may omit the field entirely. A replacement token has to be valid for the same app under the current epoch; a different app, or one that does not verify, closes the channel |
| Resumable Storage upload | the initiation, which records the admitted app and epoch in the upload session | until the session ends | continuation, status query, cancel and finalization all need a valid token for the same app. The check runs before the command is read, so a refusal neither advances nor deletes the upload, and a token that expires mid-upload leaves the resumable state intact — refresh it and resume from the offset already reached |

Only an `enforced` policy binds a channel or an upload session. Under `unenforced` a client may legitimately stop presenting a token, and binding it would enforce by the back door.

A denial happens before Security Rules and before any side effect: no user, no issued or rotated credential, no consumed action or phone code, no MFA change, no object generation, no upload session, no Firestore mutation. It renders as `PERMISSION_DENIED` with the public code in the `fireemu-code` metadata on Firestore gRPC, as an HTTP 403 Google JSON error on Firestore REST and on Auth, and as the Firebase Storage JSON error envelope with 403 on Storage. The public code is `APP_CHECK_REQUIRED` or `APP_CHECK_INVALID`; the detailed reason stays in the privileged observations.

The bypasses are explicit, and each one requires that route's own credential rather than a header shape or a path fragment:

| Surface | Bypasses | The credential it must present |
|---|---|---|
| Firestore unary gRPC and REST | yes | `Authorization: Bearer owner` exactly |
| Identity Toolkit `projects/{p}/...` Admin routes | yes | `Authorization: Bearer owner` exactly |
| Auth JWKS | yes | public-key discovery; it carries no state |
| `/emulator/v1/...` inspection routes | yes | `Authorization: Bearer $FIREEMU_CONTROL_TOKEN`. Their own guard only challenges browser requests, so the App Check path checks the token itself rather than inheriting a guard that does not run for a command-line caller |
| Control API, Emulator UI API, App Check exchange and JWKS | yes | the control token, or bootstrap and public-key discovery |
| Storage JSON API dialect (`/storage/v1/...`, Admin SDK, `gcloud`) | yes | `Authorization: Bearer owner` exactly. The dialect bypasses Security Rules without a credential, as the official Emulator does; the App Check bypass deliberately does not, or rewriting `/v0/b/...` to `/storage/v1/b/...` would defeat enforcement |
| Storage Firebase download URL | yes | a `?token=` bound in constant time to the resolved bucket, object and generation |
| Storage Firebase dialect, Auth end-user routes, Firestore end-user traffic | no | — |

Disabling Security Rules is not a bypass: with rules off every Firestore caller would otherwise be treated as the owner without presenting anything, so the App Check path verifies the owner credential itself. Neither is anonymous Auth, a loopback source, a `demo-` project name or an API key.

Reset, project deletion and snapshot restore replace the project's App Check epoch, so every token issued before the transition fails at its next verification; the observation counters reset with it. A project that has no static `appCheck.apps` registration cannot use App Check at all, so an `enforced` service denies every request that targets it.

Privileged counters and observations are at `GET /v1/sessions/{session}/appCheck/observations`, and the Emulator UI's App Check page shows them next to the configuration and the debug tokens. Unlike the rest of the control API it needs `Authorization: Bearer $FIREEMU_CONTROL_TOKEN` for every method whether or not an `Origin` is present, and its response is `Cache-Control: no-store`. Counters are grouped by service, verified app ID, callable function name for the `functions` service, category and outcome; an unverified identity aggregates into a bounded `unknown` bucket, so nothing a caller controls becomes a label. Each project -- a registered session's project and the default project alike -- keeps its own bounded ring of 256 observations and its own counters, created on first use and dropped when its session is deleted, so a flood of requests to one project never pushes another project's recent observations out of the window, and a session is served its own project and nothing else. The counters are not derived from the ring: they count every classified request since the project's state was last reset, including the observations the ring has since dropped.

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
      // FIREEMU_APP_CHECK_EMULATOR_HOST, or the Auth/control port.
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

The Firestore, Storage, Auth and Functions SDKs then attach the token themselves. `tools/sdk-smoke/appcheck.mjs` runs exactly this against `tools/sdk-smoke/fireemu.appcheck.json`. Use a clearly fake local debug secret and never a production App Check debug token.

**What is not supported.** Apps can only be registered in configuration, and adding one needs a daemon restart; the Emulator UI page manages debug tokens, not apps. Observations are polled rather than streamed, and the table of per-project rings is bounded in turn: at most 256 projects hold one at once, because a target project is resolved from a request path before anything validates it. Limited-use tokens are unsupported: `limitedUse: true` fails closed with `501 APP_CHECK_REPLAY_UNSUPPORTED` and never returns a reusable token. Production attestation providers (Play Integrity, App Attest, DeviceCheck, reCAPTCHA) are out of scope; a local token proves nothing about device integrity. Precision is `boundary-conformance`: the exact wire messages are the ones documented here, not a recording of the real services. `GET /v1/capabilities` states the exact status of all nine `APPCHECK-*` capabilities.

### Pub/Sub

The Pub/Sub emulator serves the `google.pubsub.v1` `Publisher` and `Subscriber` gRPC services on a loopback port (the official default is 8085). Like the official suite it starts only when it is configured (`emulators.pubsub`, `daemon.pubsubPort`, `--pubsub-port`) or asked for with `--only pubsub`, and `fireemu exec` then exports the canonical `PUBSUB_EMULATOR_HOST=host:port`, which the `@google-cloud/pubsub` and `firebase-admin` clients read with no other configuration.

It reproduces the documented subset the official Pub/Sub emulator implements: topics and subscriptions (create, get, list, delete, and `ListTopicSubscriptions`), publish, both unary `Pull` and `StreamingPull`, `Acknowledge`, `ModifyAckDeadline` (a deadline of zero nacks a message for immediate redelivery), ordering keys, subscription filters over attributes (`=`, `!=`, `:` existence, `hasPrefix`, `NOT` / `AND` / `OR`), dead-letter forwarding after `maxDeliveryAttempts`, and `Seek` to a timestamp. Ack deadlines and redelivery run on the virtual clock, so a test advances the control clock instead of sleeping and `await-idle` stays deterministic, and message ids and ack ids are reproducible under the daemon seed. A message published through the wire protocol also reaches subscribed Cloud Functions (`onMessagePublished` v2, `topic().onPublish` v1), so a Pub/Sub trigger now flows through real topic and subscription state; the control publish route (`POST /v1/sessions/{s}/pubsub/topics/{t}:publish`) still works, so nothing that relied on it regresses.

Resource names are validated against the documented Pub/Sub rules (3..=255 characters, a leading letter, the `[A-Za-z0-9._~%+-]` alphabet, no `goog` prefix), message size and attribute counts are bounded, and a NUL byte in an attribute or ordering key is refused (a local hardening the official emulator does not make); topics, subscriptions and retained messages are bounded so a client cannot exhaust memory. The listener binds loopback only and takes no credential, exactly like the official emulator and the other fireemu services.

Not served, and reported `UNIMPLEMENTED` where a client asks for them: snapshots (`CreateSnapshot` and seek-to-snapshot), push delivery to an endpoint (pull and streaming pull are the delivery paths), `UpdateTopic`, REST/JSON transcoding (the surface is gRPC-only), and schemas or BigQuery / Cloud Storage subscription delivery. The differential `pubsub-probe` (`conformance/pubsub-matrix.json`) records 22 parity steps and one documented divergence against the pinned official `pubsub-emulator` 0.8.35: fireemu retains acknowledged messages for a seek even when `retainAckedMessages` is false, so a seek never returns fewer messages than the official emulator returns.

### Storage

An object is at most 256 MiB; a request body is at most 260 MiB (the object boundary plus multipart framing) and is refused with `413` beyond that. Upload bytes are never duplicated on the way in: the request buffer is handed to the object store as it is, and a multipart data part is carved out of the same allocation, so a near-limit upload costs one payload-sized buffer, not two or three.

The request bodies buffered at the same time are admitted against a process-wide budget of 1 GiB (`fireemu_adapter_http::storage_server::DEFAULT_BODY_BUDGET_BYTES`, about four near-limit uploads). An upload that does not fit is refused with `503` and `Retry-After: 1` before its buffer is allocated; a body without a `Content-Length` is charged as it grows. Every charge is released as soon as the request ends, including when the upload fails on rules, a checksum or a precondition. A failed upload publishes no object.

Both dialects reproduce the pinned official Storage emulator as measured by the storage probe (`pnpm -C conformance run storage-probe`, 218 recorded steps): the Firebase protocol's resumable command grammar, download-token routes and first-read token minting, the exact rules-denial and missing-object bodies, the official route table (object update and copy are registered only on the short `/b/...` spelling; the `/storage/v1/...` spelling of those answers `501 Not Implemented`, and an unknown `GET` serves bytes through the XML-style `/{bucket}/{object}` fallback), the `metadata`-defined-versus-absent distinction, the decimal `crc32c` spelling of the Firebase dialect, list pagination whose page token names the first item of the next page, and the JSON API as a fully privileged surface on which Security Rules never run. Where fireemu deliberately keeps production behaviour the official emulator drops, the difference is pinned per step in `conformance/storage-matrix.json` through `conformance/divergences.json`: generation / metageneration preconditions and declared checksums are honoured (the official emulator ignores both and was measured to overwrite guarded objects and store corrupt payloads), resumable offsets and the JSON API `Content-Range` chunk protocol are enforced (the official emulator appends blindly and finalizes every PUT), an upload over an existing object evaluates the rules `update` method as production does (the official emulator always evaluates `create`), `resource.cacheControl` / `resource.contentLanguage` reach Storage rules, and Storage trigger events carry the production CloudEvent envelope and link hosts. Under the `firebase` profile a bearer value that does not decode as a JWT is an anonymous caller, exactly as the official emulator treats it; a token that decodes but fails the audience or signature checks is still refused, as `rules.idTokenVerification` in the compatibility contract records. With no Storage ruleset loaded fireemu allows every request, where the official emulator answers 403 `Storage Emulator has no loaded ruleset`; a daemon started from configuration always has one.

### Import and export

fireemu reads and writes the directory `firebase emulators:export` produces with
`firebase-tools@15.28.2`, so a fixture can travel between the two suites in both directions.

```sh
# start from a directory the official suite (or fireemu) exported
fireemu exec --import ./seed -- pnpm test

# keep what the run produced, in place
fireemu exec --import ./seed --export-on-exit -- pnpm test

# write the state of a suite that is already running
fireemu emulators:export ./seed
```

`--export-on-exit [dir]` writes the export on a clean exit, when the command fails, and on
SIGINT or SIGTERM. Without a directory it uses the `--import` one, as the official CLI does;
the working directory and its parents are refused, because an export replaces what the
directory holds.

**What the directory holds.** `firebase-export-metadata.json` names one section per product:

| section | files | what travels |
| --- | --- | --- |
| `firestore_export/` | `firestore_export.overall_export_metadata`, `all_namespaces/all_kinds/{all_namespaces_all_kinds.export_metadata,output-0}` | every document of the `(default)` database, in the Firestore managed-export format (LevelDB log framing, `apphosting.datastore.v3` entities) |
| `auth_export/` | `accounts.json`, `config.json` | every account with its providers, custom claims, phone and TOTP second factors, and the project's Auth configuration |
| `storage_export/` | `buckets.json`, `blobs/<id>`, `metadata/<id>.json` | every object's bytes byte for byte, with its generation, times, hashes, download tokens and custom metadata |

Everything is preserved verbatim: project ids, database ids, bucket names, object names and
account identifiers. Two consequences are worth knowing:

- the official managed export records **no document creation or update time**, so both suites
  stamp an imported document with the commit that installs it;
- a Firestore database other than `(default)` has no place in the official format, whose
  export request is hard-coded to `databases/(default)`. fireemu writes those under a
  `fireemu` member of the manifest that the official CLI ignores, so the official suite reads
  the default database and fireemu reads all of them. A TOTP second factor, which the
  official Auth emulator has no equivalent for, travels the same way under
  `mfaInfo[].totpInfo.sharedSecretKey`.

**An import is all or nothing.** Every section of the products `--only` selected is parsed
into memory first and installed together under the exclusive admission barrier, so a
malformed Storage section cannot leave a suite holding half an Auth import. Any failure
leaves the empty start state and exits `1` naming the product and the file:

```text
error: --import ./seed: storage: ./seed/storage_export/blobs: object images/hello.txt: checksum mismatch: ...
```

A section of a product `--only` did not select is skipped with a notice. A `database_export`
(Realtime Database, deferred) or `dataconnect_export` (SQL Connect, deferred) section is
**refused**: fireemu serves neither product, and importing the rest would start a suite
holding less state than the artifact records. An `accounts-<tenant>.json` is refused for the
same reason -- fireemu serves no Identity Platform tenants.

**Overwrite protection.** A directory is overwritten only when it is empty or already holds a
`firebase-export-metadata.json`. The official CLI overwrites any directory once `--force` or
`--export-on-exit` is given; fireemu applies the stricter rule always, so
`fireemu emulators:export ~/Documents` cannot replace a directory that was never an export.

#### Security policy for export artifacts

**An export directory is secret material. Treat it like a password file.**

The Local Emulator Suite stores passwords in the clear: `accounts.json` carries
`passwordHash: "fakeHash:salt=<salt>:password=<plaintext>"`, so anyone who reads an export
directory reads every test account's password. It also carries phone numbers, custom claims,
and -- for a fireemu TOTP factor -- the shared secret. Because of that:

- every directory fireemu creates for an export is `0700` and every file is `0600`;
- an export is never written to a directory that is not empty and not already an export;
- do not commit an export directory to a repository, attach it to an issue, or copy it to
  shared storage. Use `demo-` projects and throwaway passwords in any fixture you do share.

fireemu's own state stays out of the format entirely: **no App Check debug token, project
epoch or instance signing key, and no session snapshot, fault plan or text index definition
ever reaches an export directory.** Those are process secrets and session bookkeeping, not
product state, and a test asserts that an export holds only the three official sections.

Two credential rules follow from the one-way hashing fireemu uses internally:

- a password that arrived from an official import is written back exactly as it was read, so
  the export still signs in against the official suite;
- a password set through fireemu's own API has no reversible form, and its account is
  exported **without** a `passwordHash` rather than with an invented one. Re-import that
  export and the account exists with everything else intact, but its password sign-in has to
  be set up again.

Named snapshots (`POST /v1/sessions/{s}/snapshots`) remain a separate, in-memory mechanism:
they capture more than the official format can express and are never written to disk.

### Functions

`--functions <dir>` (or `functions.source` in the config) starts `tools/runner-node/index.mjs` (Node, needs the codebase's own `node_modules` with `firebase-functions` and `firebase-admin`; `express` comes with `firebase-functions`). The runner discovers the exported v2 functions and reports them; the daemon then delivers Firestore document events (`onDocumentCreated` / `Updated` / `Deleted` / `Written` with path parameters), Storage object events (`onObjectFinalized` / `Deleted` / `MetadataUpdated`), Eventarc custom events, Firebase alerts and `onSchedule` runs as JSON CloudEvents, and serves `onRequest` / `onCall` at `http://127.0.0.1:5001/{project}/{region}/{function}`. Functions declared with `retry: true` are retried with exponential backoff in virtual time; other failures are dead-lettered.

**Several codebases.** `functions` as an array in `firebase.json` is loaded whole: one runner process per codebase, all behind one functions port, routed by region and name. `--only functions:<codebase>` picks one. A function name two codebases both export is refused naming both, because the emulator serves one URL per region and name. Each codebase reads its own environment from its own `source` and labels its output `[functions:<codebase>]`. A codebase whose `runtime` is not `nodejs*` is refused with the language named: fireemu ships one loader, and the official emulator's Python and Dart paths are not it.

**Nothing exported disappears.** An export the runner cannot serve travels in the manifest as an `ignored` record — name, region, trigger family, and why — and the daemon prints one `functions[<region>-<name>]: function ignored (<family>): <reason>` line for it. `GET .../functions` lists them too. That is the official emulator's inventory (it logs `Unsupported trigger` or `Unsupported function type on <name>` and keeps the definition with `ignored: true`), with one deliberate difference: an export whose trigger family belongs to a product that is a documented gap here — deferred (Realtime Database, Remote Config) or not implemented yet (blocking identity functions) — **fails discovery** by default, naming every one, because carrying on would let a project believe a handler is live. `functions.unservedTriggers = "report"` asks for the official carry-on instead.

**Environment and parameters.** A codebase's `.env`, `.env.<projectId>`, `.env.<alias>` and `.env.local` are read in that order and in the dialect `firebase-tools`' own `lib/functions/env.js` defines, refusals included: a reserved key, a key that is not `SCREAMING_SNAKE`, a key under `X_GOOGLE_` / `FIREBASE_` / `EXT_` / `KIT_`, a line that is not an assignment, or both a project-ID and an alias file present, each stop the run with the sentence the Firebase CLI prints. `.secret.local` supplies `defineSecret` values and overrides the chain; `.runtimeconfig.json` becomes `CLOUD_RUNTIME_CONFIG` (the pinned `firebase-functions@7` has removed `functions.config()`, so nothing in the supported SDK reads it). `defineString` / `defineInt` / `defineBoolean` / `defineList` resolve from that environment exactly as they do under the official emulator, which resolves no parameters and prompts for nothing: a value nothing defines is `""`, `0`, or a `defineList` that throws, and a declared `default` is a deploy-time value the runtime never sees. The runtime is started with `FIREBASE_CONFIG` (`storageBucket`, `databaseURL`, `projectId`), `GCLOUD_PROJECT`, `GOOGLE_CLOUD_QUOTA_PROJECT`, `FUNCTIONS_EMULATOR`, `K_REVISION`, `PORT`, `TZ=UTC` and `METADATA_SERVER_DETECTION`, plus `FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE` and `K_SERVICE` set per invocation — the official emulator runs one process per trigger and sets those three once, and one fireemu runner serves a whole codebase, so they name the most recently started invocation.

**The functions port.** A path that is not a function route answers `404 Not Found`; a route whose function does not exist answers `404 Function <region>-<name> does not exist, valid functions are: <every trigger key>`, both exactly as the official emulator produces them. A function that overruns its `timeoutSeconds` gets the official answer — HTTP 500 with the body `{"code":"ECONNRESET"}` and no content type — and the daemon logs `Your function timed out after ~Ns.`; unlike the official emulator, the runner is not killed, because it serves the whole codebase rather than one trigger. An `onRequest` function on a loopback origin gets the CORS the official emulator's `enableCors` gives it: a preflight answered `204` with the origin reflected and `GET,HEAD,PUT,PATCH,POST,DELETE`, and `Access-Control-Allow-Origin` on the ordinary answer. **A non-loopback `Origin` is refused with `403`**, which the official emulator does not do: its runtime reflects any origin, so a page anywhere on the internet can drive a developer's local callable and read the result. That is a deliberate divergence, recorded in `conformance/fixtures/functions/http-routing-cors-and-timeouts.json`.

**Cloud Tasks.** The functions port serves the enqueue surface too, and exports `CLOUD_TASKS_EMULATOR_HOST` (without a scheme, as the official CLI spells that one), so `getFunctions().taskQueue("myJob").enqueue(payload)` reaches an `onTaskDispatched` function with nothing configured. The queue *is* the function: it exists exactly while the function does, its default URI is that function's own `/{project}/{region}/{function}` URL, and a dispatch carries `X-CloudTasks-QueueName` (the internal `queue:{project}-{location}-{name}` key the official emulator sends), `X-CloudTasks-TaskName`, `X-CloudTasks-TaskRetryCount` (0 on the first delivery), `X-CloudTasks-TaskExecutionCount`, `X-CloudTasks-TaskETA` and, after a failure, `X-CloudTasks-TaskPreviousResponse`. Retries follow the official backoff (`maxAttempts` 3, `minBackoffSeconds` 0.1, doubling to a one-hour ceiling by default) in **real time**, as they do upstream and in production, and `awaitIdle` waits for a task across its attempts. Two upstream behaviours are kept: a `scheduleTime` does not delay dispatch (nothing in the official dispatch loop consults it either), and a non-5xx failure is what bumps the execution count. One is not: a task may not name a URL of its own, because a local emulator making an arbitrary outbound request on a caller's say-so is a request-forgery surface nothing else here offers.

**Eventarc and Firebase alerts.** The functions port also serves `POST /projects/{p}/locations/{l}/channels/{c}:publishEvents` and `POST /google/publishEvents`, and exports `CLOUD_EVENTARC_EMULATOR_HOST` for them, so `firebase-admin`'s `getEventarc().channel().publish()` reaches `onCustomEventPublished` handlers with nothing configured. The proto CloudEvent the SDK sends is converted the way the official emulator converts it, and `filters` are matched the way it matches them. Firebase alerts (`onAlertPublished` and the Crashlytics, Billing, App Distribution and Performance helpers) go through the same door and no other: the official suite has no alerts emulator and no injection route either — its UI fires one by POSTing the alert CloudEvent to `/google/publishEvents`, and so can you.

```sh
curl -X POST http://127.0.0.1:5001/google/publishEvents -H 'content-type: application/json' -d '{
  "events": [{"type": "google.firebase.firebasealerts.alerts.v1.published",
              "alerttype": "crashlytics.newFatalIssue", "appid": "1:1:web:a",
              "id": "1", "source": "//firebasealerts.googleapis.com/projects/1", "specversion": "1.0",
              "time": "2026-01-01T00:00:00Z",
              "data": {"createTime": "2026-01-01T00:00:00Z", "endTime": "2026-01-01T00:00:00Z",
                       "payload": {"issue": {"id": "1", "title": "App.main"}}}}]}'
```

```sh
curl -X POST http://127.0.0.1:9099/v1/sessions/default:awaitIdle -d '{"timeoutSeconds": 30}'   # wait for triggers
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 600}'     # runs due schedules (and due retries)
curl -X POST http://127.0.0.1:9099/v1/sessions/default/functions/nightly:run                  # run a schedule now
curl http://127.0.0.1:9099/v1/sessions/default/functions                                      # queue status
```

Invocations have a real-time deadline (`timeoutSeconds`); a handler that overruns it is dead-lettered (or retried) but keeps its concurrency slot, and `await-idle` keeps waiting, until it actually finishes. The runner inherits only an allowlisted environment (no cloud credentials; Application Default Credentials are blocked) plus the emulator hosts. `POST /v1/sessions/{s}/reset` waits for requests in flight, wipes Firestore, Auth and Storage, and kills and restarts the runner, so a handler that was still running cannot write into the new session. Schedules accept IANA time zones with daylight-saving rules (`scheduler.defaultTimeZone`, `timeZone` on the function); `scheduler.overlap` chooses `allow` (default), `skip`, `queue` or `reject` for a run that comes due while the previous one is still queued or running. `firebase-functions/v1` firestore, storage and `pubsub.schedule` handlers are supported alongside v2.

Diagnostic retention is bounded by a fixed budget: the daemon keeps the 1000 most recent invocation records, the 500 most recent dead letters and the 1000 most recent terminal event records, and drops the older ones. `GET .../functions` and the UI show that window; the `succeeded`, `deadLettered` and `overlapRejected` counters in the queue status are cumulative and unaffected by it, so a long-running session keeps exact totals with bounded memory. Every retained record carries a monotonic sequence inside an explicit generation (a reset bumps the generation), and the UI's log stream asks only for the records after the cursor it holds; when its cursor is from another generation or older than the retained window, the stream sends a `resync` event with the current window instead of a delta with a hole in it. The browser keeps at most the 500 most recent invocation rows.

Browser pages on a loopback origin must send `Authorization: Bearer <control token>` (printed at start as `FIREEMU_CONTROL_TOKEN`) to privileged control routes (reset, clock, rules, functions, `awaitIdle`); command-line clients need no token.

Pub/Sub topic triggers (`onMessagePublished`, v1 `topic().onPublish`) receive messages published through the control API (`POST /v1/sessions/default/pubsub/topics/{topic}:publish` with `{"messages": [{"json": {...}, "attributes": {...}}]}`, or the Pub/Sub REST shape `/v1/projects/{project}/topics/{topic}:publish` with base64 `data`). Auth user created / deleted events reach v1 `auth.user().onCreate` / `onDelete` handlers. `*WithAuthContext` Firestore triggers carry `authtype` / `authid` of the principal that committed. `scheduler.catchUp` chooses what happens to schedule runs that became due while the clock moved: `all` (default), `latest` (one run per job), `none`. `latest` and `none` compute the run they keep directly instead of walking the missed ones, so a jump of years costs the same as a jump of minutes; what they drop appears as one `skipped: catch-up ...` record per job and clock change, carrying a count that is exact up to `scheduler.maxCatchUpRuns` (1000) and reported as `at least N runs` beyond it (an `every N minutes` schedule is always counted exactly). `tools/sdk-smoke/functions.mjs` with `tools/sdk-smoke/functions-project/` exercises all of it (pin the clock with `--config tools/sdk-smoke/fireemu.smoke.json`: schedule counts depend on it). Not served, and refused by name rather than ignored: blocking identity functions (`beforeUserCreated` / `beforeUserSignedIn`, v1 `beforeCreate` / `beforeSignIn`), and Realtime Database and Remote Config triggers (there is no such service in the daemon). Hot reload of a codebase's source is not implemented either: a change needs a restart, and `ignore` is recorded rather than driving a watcher.

Browser apps point the web SDK at the same ports (`connectFirestoreEmulator(db, "127.0.0.1", 8080)`, `connectAuthEmulator(auth, "http://127.0.0.1:9099")`); the Firestore port serves gRPC, REST and the WebChannel transport, and both ports answer CORS preflights. `FIREEMU_TRACE_WEBCHANNEL=1` traces the channel protocol on stderr.

| Crate | Purpose | Dependencies |
|---|---|---|
| `fireemu-core-types` | validated identifiers, logical time, edition capabilities, deterministic adapters | none |
| `fireemu-core-limits` | versioned limit catalogs and the warning / rejection engine | none |
| `fireemu-core-session` | session lifecycle, epoch isolation, virtual clock, idle ledger | none |
| `fireemu-core-events` | event state machine, retry policy, outbox | none |
| `fireemu-core-firestore` | field paths, value ordering, storage-size formula, query AST + Standard limits, conservative index validator, local execution store (MVCC, transactions, queries, aggregations) | none |
| `fireemu-core-rules` | Security Rules parser, static limit linter (`RULES-LINT-1`) and evaluator subset with runtime budgets | none |
| `fireemu-core-auth` | users, custom claims, ID token claims, unsigned emulator tokens and the `IdTokenSigner` contract for signed ones, TOTP second factor (RFC 6238) | none |
| `fireemu-core-storage` | Cloud Storage objects: opaque UTF-8 names, generations, metadata, listing, resumable uploads, MD5 / CRC32C | none |
| `fireemu-core-functions` | function manifest, document path patterns, cron / App Engine schedules, CloudEvents attributes | none |
| `fireemu-proto-firestore` | vendored Firestore v1 protos and checked-in generated code | prost, prost-types, tonic |
| `fireemu-adapter-grpc` | Firestore v1 service: strict gateway, local backend, `Write` / `Listen` streams, Rules enforcement, optional upstream proxy | tonic, tokio |
| `fireemu-adapter-http` | Identity Toolkit REST subset (sign-up, password sign-in, custom claims, TOTP MFA, refresh, Admin SDK accounts), RS256 session signing + JWKS, the Storage surface and the control API (clock, rules, capabilities, await-idle) | hyper, tokio, serde_json, rsa, sha2 |
| `fireemu-adapter-functions` | runner process protocol, event dispatch with retries, scheduler, await-idle, HTTP function proxy | tokio, hyper, serde_json |
| `fireemu` | the daemon binary (`up`, `doctor`, `capabilities`) | tokio, serde_json |

`fireemu-core-*` crates are `std`-only and forbid `unsafe` (ADR-001, ADR-007).

## Layout

```text
crates/            core crates (std-only) and, later, protocol / runtime shells
npm/               the published `fireemu` launcher, the `@fireemu/*` platform-package
                   generator, and the release scripts (version stamping, local pack proof)
spec/limits/       versioned limit catalogs (single source of truth for limit values)
tools/             development tools; never linked into the release binary
                   (`tools/runner-node` is the exception: it ships in every platform package)
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
cargo run -p compat-check
cargo run -p config-schema-check
cargo run -p proto-gen -- check            # needs protoc
node npm/scripts/pack-local.mjs            # pack this host's npm packages from target/release
RUSTFLAGS="--cfg loom" cargo test -p fireemu-verification-loom --release
TLA2TOOLS_JAR=/path/to/tla2tools.jar verification/tla/run-tlc.sh
```

`traceability-check` resolves every artifact the requirement ledger names: a `kani` artifact must
be a `#[kani::proof]` function under `verification/kani`, a `property` artifact a test function
under a `tests/` directory (the core ones live in `verification/property/tests`), a `fuzz`
artifact a `fuzz/fuzz_targets/<name>.rs` file, and a `conformance` artifact an existing path.
Artifacts that are decided but not written yet are written as `pending:<name>`; a pending artifact
is printed on every run and never counts as evidence. See
[docs/verification-ledger.md](docs/verification-ledger.md) for the schema and the gate.

`compat-check` is the same idea for the public compatibility claim. It reads
`spec/compatibility/contract.json`, the capability manifest data in
`crates/fireemu/src/capabilities.json` (which `crates/fireemu/src/control.rs` embeds with
`include_str!`, so it is exactly what `GET /v1/capabilities` publishes) and this README, and it
fails when an `implemented` capability is bound to no existing test or conformance fixture, when
the manifest and the contract disagree on a status, when this README does not carry the claim
sentence, when a deferred or not-planned product reads as supported, when two public statements
contradict each other, or when a compatibility profile names a configuration key the canonical
schema does not define. See
[docs/compatibility-contract.md](docs/compatibility-contract.md) for the schema and the rules.

The `pr` and `ci` profiles fail a run in which a process started by a test still holds the test's
captured stdout or stderr 30 seconds after the test process exited (`leak-timeout` in
`.config/nextest.toml`, which records how the period was measured). That signal cannot see a
process that closed or redirected those handles, so tests that start daemons or shells also assert
a process census (`crates/fireemu/tests/census/mod.rs`);
`crates/fireemu/tests/leak_fixture.rs` proves both, by running intentional-leak fixtures
through a nested nextest in their own process group and reaping them unconditionally.

The SDK smokes run the real SDKs against a release build; `tools/sdk-smoke/README.md` has the
full list. The discovery one is:

```sh
cargo build --release -p fireemu
./target/release/fireemu exec --config tools/sdk-smoke/fireemu.rules-unit-testing.json \
  --project demo-app --firestore-port 28180 --http-port 29199 --storage-port 29299 \
  --functions-port 25101 --ui-port 0 --hub-port 24400 \
  -- sh -c 'cd tools/sdk-smoke && node rules-unit-testing.mjs'
```

TLC needs Java 21 and TLA+ Tools 1.8.0
(`sha256 eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`).
Kani harnesses live in `verification/kani` and run with `cargo kani`. Harnesses that allocate
on the heap currently fail on macOS with Kani 0.67 ("Function `malloc` with missing definition
is unreachable"); the allocation-free harnesses verify. Tracked as a known environment issue.

## Protobuf

`crates/fireemu-proto-firestore/proto/` vendors the Firestore v1 protos from googleapis at the commit
in `proto/UPSTREAM_COMMIT`; `tools/proto-gen` regenerates the checked-in Rust code (ADR-008).
A normal build never runs `protoc`.

## Limit catalogs

Limit values are declared once in `spec/limits/<catalog-id>.json` and rendered into
`crates/fireemu-core-limits/src/generated/` by `tools/limit-catalog-gen`. Catalogs are immutable:
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

## Conformance

`conformance/` is an opt-in, black-box differential suite: one Node scenario corpus runs against
the official Local Emulator Suite (`firebase-tools`, pinned to an exact version in
`conformance/package.json`) and against `fireemu`, and every step is recorded as `parity`,
`documented-divergence`, `debt` or `pending`.

```sh
pnpm -C conformance install
pnpm -C conformance run oracle   # record fixtures/, ORACLE.md and DEBT.md (needs Java)
pnpm -C conformance run check    # replay fireemu against the fixtures; fails on drift
```

Beside the scenario corpus, two differential probes compare the runtimes directly through the
same routes on both sides and fail on any unrecorded difference: the Security Rules language
matrix (`pnpm -C conformance run matrix:check`, 680 expression claims plus whole-program
probes) and the Firestore semantics matrix (`pnpm -C conformance run firestore:check`, 324
REST rows over values, filters, cursors, collection groups, aggregations, listings, writes,
transforms, transactions, error shapes and the emulator routes). Every deliberate difference
is pinned to fireemu's recorded answer in a divergence register
(`conformance/src/firestore-probe/divergences.mjs`) and published in
`spec/compatibility/contract.json`; the largest one is the transaction model -- fireemu is
optimistic (the transaction whose read set was overwritten is `ABORTED` at commit, which the
SDKs retry, and the out-of-band write succeeds), where the official emulator locks the read
set and instead refuses the out-of-band writer after a lock timeout.

`run oracle` is the only step that needs Java and the downloadable emulator jars. `run check`
needs a built `fireemu` and replays the corpus against the committed fixtures, so it is
the part a contributor runs; it fails the process on a `parity` row that drifted, a documented
divergence that moved off its recorded value, a step no fixture describes, or a scenario that
faulted. `debt` rows are reported and never gate: gating them would only freeze the mismatch.

`conformance/ORACLE.md` is regenerated by the recorder from the installed CLI -- its version, the
lockfile integrity, and every bundled emulator artifact with its upstream SHA-256 -- so a fixture
can never claim an oracle the tree did not produce. `conformance/DEBT.md` lists every row that is
not parity. Only `documented-divergence` rows are intentional, and each one names the text that
publishes it (this README, a capability manifest entry, or a specification section).

Neither this suite nor the manifest claims replacement of the Emulator Suite. The oracle is the
official *emulators*, not production: the official emulators implement no App Check enforcement
at all, so every row that would need a real project is recorded `pending` with that reason rather
than invented, and no `boundary-conformance` precision is raised on this evidence.

Not covered in the current slice: browser / WebChannel, the Android, Apple, Unity, Java, Python
and Go SDKs, and the official products fireemu does not implement.

## License

Apache-2.0 (see `Cargo.toml`). A `LICENSE` file will be added before the first public release.
