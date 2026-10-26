# Realtime Database SDK smokes

Five smokes drive the Realtime Database through the pinned client SDKs and compare what the SDKs report with a recording of the official database emulator (`firebase-database-emulator-v4.11.2.jar`, the one firebase-tools 15.28.2 runs):

| Smoke | What it drives |
|---|---|
| `crud` | writes, reads, updates, push ids, server values, priorities, a query, a transaction and removals with `firebase` 12.18.0, then the same with `firebase-admin` 14.3.0 |
| `listen` | value events of one app following another app's writes, including an equal-value write, a transaction and the listener's own write |
| `queries` | one reader app per query (`limitToFirst`, `limitToLast`, `orderByPriority`, a key range, `orderByChild` without an index), so each opens a tagged listen on the server |
| `disconnect` | onDisconnect `set` with a server timestamp, `update` with an increment, `remove`, `setWithPriority` and a cancelled write, run when the app goes offline, as another app reads them |
| `long-polling` | the web SDK in headless Chromium (Playwright 1.62.1) with `forceLongPolling()`, so it speaks the `.lp` long-polling transport, ending with onDisconnect writes |

The recordings in `fixtures/official-emulator-4.11.2/` are what the official emulator answered. They are comparison targets, not evidence of production behaviour. Server timestamps are replaced with `"<TS>"` and push ids with their length before comparing.

## Running against fireemu

```sh
npm ci --prefix tools/sdk-smoke-database
npx --prefix tools/sdk-smoke-database playwright install chromium   # once, for long-polling
fireemu exec --only database -- node tools/sdk-smoke-database/run.mjs
```

`fireemu exec` sets `FIREBASE_DATABASE_EMULATOR_HOST`, which `run.mjs` reads; no configuration file is needed. Each smoke prints `same as the official emulator` or the first difference, and the exit status is 1 when any smoke differs. `--only crud,disconnect` runs a subset and `--host 127.0.0.1:9000` names a server explicitly.

## Tests

```sh
npm ci --prefix tools/sdk-smoke-database --ignore-scripts
npm test --prefix tools/sdk-smoke-database
```

The tests are offline: they run against fakes and committed fixtures, and need no Google endpoint, no credential, no official emulator jar and no fireemu binary. CI runs them (the `sdk-smoke-database` job). Only `rtdb-residual-page.test.mjs` needs headless Chromium (`npx --prefix tools/sdk-smoke-database playwright install chromium`); on a machine without it the file is skipped, and with `FIREEMU_REQUIRE_BROWSER=1` (as in CI) a missing browser fails it instead.

## Recording the official emulator again

The recordings come only from the pinned jar, `firebase-database-emulator-v4.11.2.jar` with SHA-256 `b70d99344caf17c98b6f910fa8f6edf32a7c016cb1035e8915f70d38901eb97f` (the value `spec/compatibility/contract.json` pins). Fetch it with the pinned firebase-tools, which puts it in `~/.cache/firebase/emulators/`, then record:

```sh
npx firebase-tools@15.28.2 setup:emulators:database
node tools/sdk-smoke-database/run.mjs --record tools/sdk-smoke-database/fixtures/official-emulator-4.11.2
```

`--record` checks the jar's SHA-256 and refuses any other file, starts it on a free loopback port and stops it afterwards; `--jar <path>` names a jar kept elsewhere. A recording that changes between two runs is a timing problem in the smoke, not a difference between servers.

`npm test` checks the comparison helper, the jar check, the CV11 recorder, the production fixtures and the production comparisons below.

## CV11 genuine-auth recorder

`cv11-genuine-auth.mjs` runs one scenario (`cv11-genuine-auth-page.js`) with the web SDK in headless Chromium for four profiles (round 1 and 2, WebSocket and long polling). Per profile it creates two email/password users, seeds `{value: round}` at each user's scope `<prefix>/r<round>/users/<uid>` under owner-only Rules, and records: sign-in, the first listener's value, a forced token refresh, sign-out and whether the listener is cancelled, a second sign-in and listener, user B reading its own scope and user A's, deletion of user A through the admin API, a write after the deletion, a forced refresh after it, and whether the second listener is cancelled. The journal holds steps, event types, listener epochs, error codes and data shapes only.

```sh
node tools/sdk-smoke-database/cv11-genuine-auth.mjs local --out <new dir> --modules <node_modules with firebase 12.18.0 and playwright 1.62.1> --fireemu <fireemu binary>
node tools/sdk-smoke-database/cv11-genuine-auth.mjs compare <a>/journal.json <b>/journal.json
```

`local` starts `fireemu up --only auth,database` (strict profile) on free ports and stops it afterwards. `production` refuses to run without `--packet <file>` and a matching `--packet-sha256`, and the packet pins the SHA-256 of both source files. Every admin request is counted against fixed caps before it is sent; any answer other than a complete 2xx or 4xx is unknown, and an unknown create or delete leaves the run `needs-recovery` and is never re-sent.

## Residual recorder (CV08 reconnect and ordering, CV10 onDisconnect cancel and re-register)

`rtdb-residual.mjs` runs two scenarios (`rtdb-residual-page.js`) for four profiles each (round 1 and 2, WebSocket and long polling) with the web SDK in headless Chromium. The page has no account: the Rules give the anonymous client its own run prefix.

- `cv08`: an observer listens (value and child events on a `limitToFirst(2)` and a `limitToLast(2)` window, a path gated by another path, a control path), drops the `limitToLast` window (query-scoped removal), goes offline, queues three writes, the writer changes the server (including the gate), the observer comes back, a fresh listen on the dropped window starts, and later writes show which listeners survived.
- `cv10`: a writer registers `set`, `update` (with a null and a server value) and `remove` onDisconnect writes, cancels and re-registers, cancels a parent, a Rules change denies two paths between registration and firing, the writer goes offline, and the observer records what fires and the final values. Long-polling profiles wait for the server's idle close (about 105 s).

```sh
node tools/sdk-smoke-database/rtdb-residual.mjs local --fireemu <fireemu binary> --out <new dir> [--profile strict|emulator] [--modules <node_modules>]
node tools/sdk-smoke-database/rtdb-residual.mjs compare <production journal.json> <local journal.json> [--out <comparison.json>]
```

`compare` judges the second journal against the first with `rtdb-residual-judge.mjs`: a step is compared in the recorded order where the first journal's two rounds of one transport agree, sorted where they hold the same events in another order, and not judged (needs-review) where they differ or where a `timeout` or `error` row was recorded. The order between the writer's and the observer's rows is a race of two connections and is not compared. `production` needs a packet, like the CV11 recorder. `rtdb-residual-page.test.mjs` runs the scenarios in Chromium against a stub SDK that delivers nothing, to exercise the bounded waits (`timeout` rows), rejections, the Rules probe and the masks; it is skipped when Chromium cannot be launched. `adc-preflight.mjs` checks the ADC token before a production run (one tokeninfo POST, token in the body; stops unless it has `userinfo.email`, `firebase.database` or `cloud-platform`, and an email): the residual recorder and the CV11 recorder (`cv11-genuine-auth.mjs`, whose production branch is otherwise unchanged) call it first, and `node adc-preflight.mjs --gcloud <path>` can be run before any other recorder. `local --official` runs the same scenarios against the pinned official emulator jar as a reference.

## Production comparisons

Three tools compare a local `fireemu` (strict profile, `fireemu up --only auth,database` on free loopback ports, stopped afterwards) with production recordings committed under `fixtures/`. None of them sends anything to production.

```sh
node tools/sdk-smoke-database/rest-replay.mjs local --fireemu <fireemu binary> --out <new dir>
node tools/sdk-smoke-database/cv07-ondisconnect.mjs local --fireemu <fireemu binary> --out <new dir> [--modules <node_modules>]
node tools/sdk-smoke-database/cv11-genuine-auth.mjs local --fireemu <fireemu binary> --out <new dir>
node tools/sdk-smoke-database/cv11-fixture.mjs compare <new dir>/journal.json --out <comparison.json>
```

- `rest-replay.mjs` sends the 124 REST requests of `fixtures/production-rest.json` (two rounds of `production-corpus.mjs`) in recorded order under the Rules production had, then loads the 48 M14 Rules sources with the bytes the recorder sent. A REST row is `MATCH` when status, body bytes and ETag are equal, `KNOWN_DIFFERENCE` when only the JSON member order differs on the two rows where production answered in another order (`patch-update-nested-and-add` keeps the request's order, `query-get-1` lists children in query order), and `MISMATCH` otherwise. It writes `comparison.json` and exits 1 on any `MISMATCH`.
- `cv07-ondisconnect.mjs` runs the production onDisconnect scenario (`sdkScenario` in `production-live.mjs`) for round 1 and 2 over WebSocket and long polling in headless Chromium and compares the 36 durable SDK events, projected on eight keys, in order with `fixtures/production-sdk-ondisconnect.json`. The onDisconnect fire delay is judged as a tolerance: within 2 s over WebSocket, and within 5 s of production's 100.8 s to 104.0 s over long polling, where the server drops the idle connection. A run takes about 3.5 minutes. `cv07-ondisconnect.mjs fixture <sdk-events.jsonl> <out>` rebuilds the fixture from the private recording.
- `cv11-fixture.mjs compare` judges a local CV11 journal against `fixtures/production-cv11-genuine-auth.json` (production run of 2026-10-25, timings removed) with `compareRecorded`: every event in recorded order, except the two events of step `write-after-delete` (the admin acknowledgement and the listener value, which production delivered in both orders). The recorder's own `compare` (`compareJournals`) sorts the events of every step and is not the closure judge. `fixtures/local-cv11-genuine-auth.json` is the journal of the closure binary, and `npm test` checks that it matches.
