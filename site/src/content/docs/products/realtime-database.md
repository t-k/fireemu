---
title: Realtime Database
description: The Firebase Realtime Database, served without a compatibility claim yet.
---

Fireemu serves the Firebase Realtime Database at `127.0.0.1:9000`. It is an open gap in the [compatibility contract](../../compatibility/): the transports the SDKs use are served and compared with the official emulator, but some features are missing and there is no compatibility claim yet.

The database starts when it is selected or configured: `--only database`, `emulators.database` in `firebase.json`, `daemon.databasePort`, or `--database-port`. Without any of them the default run leaves port 9000 free. `fireemu exec` sets `FIREBASE_DATABASE_EMULATOR_HOST`, which the Admin SDK reads; web and mobile clients call `connectDatabaseEmulator`.

```sh
npx fireemu exec --only database -- npm test
```

## What is served

- The REST API (`.json` paths): reads, writes, updates, push ids, conditional requests with ETags, `shallow`, `print`, `format=export`, queries and event streams (`Accept: text/event-stream`).
- The realtime protocol over WebSocket and over long polling (`forceLongPolling()`), with listens, queries, transactions and server values.
- Namespaces, chosen by the `ns` query parameter or the first label of the host name, as on the official emulator. A session reset empties the namespaces of the project it resets (`<project>` and `<project>-default-rtdb`).

`tools/sdk-smoke-database` in the repository drives these through the pinned `firebase` and `firebase-admin` SDKs and compares the results with a recording of the official emulator.

## Security Rules

Rules are not evaluated yet. A `database` section in `firebase.json` is accepted and reported with a notice, and every request is answered as for a database without rules. By default that is open to everyone, as the official emulator serves a database with no rules file. With `database.defaultAccess = "locked"` (the `productionExact` default, strict profile only) only the emulator's `owner` credential, which the Admin SDK sends to an emulator, can read and write.

## Not supported yet

- Security Rules evaluation.
- `onDisconnect` operations.
- Import and export: a `database_export` section is refused on import, and nothing is exported.
- Realtime Database triggers for Cloud Functions, and a view in the Emulator UI.

Where production has not been observed, Fireemu follows the official emulator (number forms such as `1.0`, a write of an equal value, priorities, refusal texts, long-polling framing). That behavior is provisional and may change once production is observed.
