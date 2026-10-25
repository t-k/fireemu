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

## Recording the official emulator again

The recordings come only from the pinned jar, `firebase-database-emulator-v4.11.2.jar` with SHA-256 `b70d99344caf17c98b6f910fa8f6edf32a7c016cb1035e8915f70d38901eb97f` (the value `spec/compatibility/contract.json` pins). Fetch it with the pinned firebase-tools, which puts it in `~/.cache/firebase/emulators/`, then record:

```sh
npx firebase-tools@15.28.2 setup:emulators:database
node tools/sdk-smoke-database/run.mjs --record tools/sdk-smoke-database/fixtures/official-emulator-4.11.2
```

`--record` checks the jar's SHA-256 and refuses any other file, starts it on a free loopback port and stops it afterwards; `--jar <path>` names a jar kept elsewhere. A recording that changes between two runs is a timing problem in the smoke, not a difference between servers.

`npm test` checks the comparison helper, the jar check and the CV11 recorder below.

## CV11 genuine-auth recorder

`cv11-genuine-auth.mjs` runs one scenario (`cv11-genuine-auth-page.js`) with the web SDK in headless Chromium for four profiles (round 1 and 2, WebSocket and long polling). Per profile it creates two email/password users, seeds `{value: round}` at each user's scope `<prefix>/r<round>/users/<uid>` under owner-only Rules, and records: sign-in, the first listener's value, a forced token refresh, sign-out and whether the listener is cancelled, a second sign-in and listener, user B reading its own scope and user A's, deletion of user A through the admin API, a write after the deletion, a forced refresh after it, and whether the second listener is cancelled. The journal holds steps, event types, listener epochs, error codes and data shapes only.

```sh
node tools/sdk-smoke-database/cv11-genuine-auth.mjs local --out <new dir> --modules <node_modules with firebase 12.18.0 and playwright 1.62.1> --fireemu <fireemu binary>
node tools/sdk-smoke-database/cv11-genuine-auth.mjs compare <a>/journal.json <b>/journal.json
```

`local` starts `fireemu up --only auth,database` (strict profile) on free ports and stops it afterwards. `production` refuses to run without `--packet <file>` and a matching `--packet-sha256`, and the packet pins the SHA-256 of both source files. Every admin request is counted against fixed caps before it is sent; any answer other than a complete 2xx or 4xx is unknown, and an unknown create or delete leaves the run `needs-recovery` and is never re-sent.
