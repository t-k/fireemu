# Realtime Database SDK smokes

Four smokes drive the Realtime Database through the pinned client SDKs and compare what the SDKs report with a recording of the official database emulator (`firebase-database-emulator-v4.11.2.jar`, the one firebase-tools 15.28.2 runs):

| Smoke | What it drives |
|---|---|
| `crud` | writes, reads, updates, push ids, server values, priorities, a query, a transaction and removals with `firebase` 12.18.0, then the same with `firebase-admin` 14.3.0 |
| `listen` | value events of one app following another app's writes, including an equal-value write, a transaction and the listener's own write |
| `queries` | one reader app per query (`limitToFirst`, `limitToLast`, `orderByPriority`, a key range, `orderByChild` without an index), so each opens a tagged listen on the server |
| `long-polling` | the web SDK in headless Chromium (Playwright 1.62.1) with `forceLongPolling()`, so it speaks the `.lp` long-polling transport |

The recordings in `fixtures/official-emulator-4.11.2/` are what the official emulator answered. They are comparison targets, not evidence of production behaviour. Server timestamps are replaced with `"<TS>"` and push ids with their length before comparing.

## Running against fireemu

```sh
npm ci --prefix tools/sdk-smoke-database
npx --prefix tools/sdk-smoke-database playwright install chromium   # once, for long-polling
fireemu exec --only database -- node tools/sdk-smoke-database/run.mjs
```

`fireemu exec` sets `FIREBASE_DATABASE_EMULATOR_HOST`, which `run.mjs` reads; no configuration file is needed. Each smoke prints `same as the official emulator` or the first difference, and the exit status is 1 when any smoke differs. `--only crud,listen` runs a subset and `--host 127.0.0.1:9000` names a server explicitly.

## Recording the official emulator again

The recordings come only from the pinned jar, `firebase-database-emulator-v4.11.2.jar` with SHA-256 `b70d99344caf17c98b6f910fa8f6edf32a7c016cb1035e8915f70d38901eb97f` (the value `spec/compatibility/contract.json` pins). Fetch it with the pinned firebase-tools, which puts it in `~/.cache/firebase/emulators/`, then record:

```sh
npx firebase-tools@15.28.2 setup:emulators:database
node tools/sdk-smoke-database/run.mjs --record tools/sdk-smoke-database/fixtures/official-emulator-4.11.2
```

`--record` checks the jar's SHA-256 and refuses any other file, starts it on a free loopback port and stops it afterwards; `--jar <path>` names a jar kept elsewhere. A recording that changes between two runs is a timing problem in the smoke, not a difference between servers.

`npm test` checks the comparison helper and the jar check.
