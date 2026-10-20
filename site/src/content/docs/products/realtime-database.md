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
- `onDisconnect` writes (`set`, `update`, `remove`, `cancel`): they run when the connection ends, however it ends (the app goes offline, the socket closes, or a long-polling client stops asking), as one update with their server values resolved at that moment. An update the database cannot apply, such as a priority for a node that is not there, writes none of them, as on the official emulator. They do not run when fireemu itself stops, as the official emulator does not run them when it stops, and a session reset drops those registered for the projects it resets. Registrations are bounded only as plain writes are.
- Namespaces, chosen by the `ns` query parameter or the first label of the host name, as on the official emulator. A session reset empties the namespaces of the project it resets (`<project>` and `<project>-default-rtdb`).

`tools/sdk-smoke-database` in the repository drives these through the pinned `firebase` and `firebase-admin` SDKs and compares the results with a recording of the official emulator.

## Security Rules

Security Rules are evaluated as the official emulator (firebase-database-emulator v4.11.2) evaluates them: `.read`, `.write`, `.validate` and `.indexOn`, with `auth`, `now`, `root`, `data`, `newData`, `query` and `$` variables, over REST, event streams and the realtime protocol, onDisconnect writes included (checked when registered and again when they run). The `database` section of `firebase.json` is loaded as firebase-tools 15.28.2 loads it: the single form into `<project>-default-rtdb`, the array form into each entry's deploy target instances (from `.firebaserc`) or instance. A file that does not load stops the start with the file, line and column; a changed file is loaded again, and a change that does not load keeps the rules in force and prints why. `GET` and `PUT /.settings/rules.json?ns=<instance>` read and replace an instance's rules with an administrator credential. A rules change, or a client signing in or out, cancels the listens and event streams the new rules no longer allow. Under the `emulator` profile credentials are read as the official emulator reads them: any `Authorization: Bearer <token>` or `access_token` is an administrator that rules do not apply to (safe only because the listener is loopback), `auth=<ID token>` is the user the token names with its custom claims as members of `auth`, and any other `auth` value is anonymous. Under `strict` (the default) only the emulator's `owner` credential, which the Admin SDK sends, is an administrator, `auth=` must be a token fireemu's Auth verifies for the instance's project (`<project>-default-rtdb`, or the daemon's project for a named instance; `auth.allowUnsignedIdTokens` decides the `@firebase/rules-unit-testing` mock tokens), and any other credential is refused with 401. The official emulator's own regular-expression dialect is not followed yet: its load refusals are (`\s` and `\S` included), and a pattern fireemu does not read as it does (`(?…)`, `[[:class:]]`, an escaped letter other than `\d \D \w \W`, `x**`) is an error that makes the rule false whether or not it is negated. An expression nests at most 600 levels (`&&`, `||` and `+` chains of any length count once), a local safety budget. An instance without rules follows `database.defaultAccess`: open, as the official emulator serves it, or, with `"locked"` (the `productionExact` default, strict profile only), only the emulator's `owner` credential, which the Admin SDK sends against an emulator; under `"locked"` other administrator tokens are held to the rules too. The start banner's `database rules:` line names each file and its instance, and what an instance without rules allows.

## Not supported yet

- Rules coverage reports (the official emulator's `/.inspect/coverage`).
- Import and export: a `database_export` section is refused on import, and nothing is exported.
- Realtime Database triggers for Cloud Functions, and a view in the Emulator UI.

Where production has not been observed, Fireemu follows the official emulator (number forms such as `1.0`, a write of an equal value, priorities, refusal texts, long-polling framing). That behavior is provisional and may change once production is observed.
