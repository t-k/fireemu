---
title: Realtime Database
description: The Firebase Realtime Database with Security Rules, export and import, served without a compatibility claim yet.
---

Fireemu serves the Firebase Realtime Database at `127.0.0.1:9000`: the REST API, the realtime protocol the SDKs use, Security Rules, and export and import in the Firebase CLI's format. It is compared with the official emulator (firebase-database-emulator v4.11.2, which firebase-tools 15.28.2 runs). Production has not been observed yet, so the [compatibility contract](../../compatibility/) lists it as an open gap with no compatibility claim, and behavior copied from the official emulator may change once production is observed (see [Provisional behavior](#provisional-behavior)).

## Start it

The database starts when it is selected or configured. Without any of the following, the default run leaves port 9000 free:

- `--only database` (with other services: `--only auth,firestore,database`);
- `emulators.database` in `firebase.json`, as `firebase init` writes it;
- `daemon.databasePort` in `fireemu.toml`, or `--database-port`.

```sh
npx fireemu exec --only database -- npm test
```

```json
{
  "emulators": { "database": { "port": 9000 } }
}
```

The start banner shows the address and the rules in force:

```text
  database:         127.0.0.1:9000   FIREBASE_DATABASE_EMULATOR_HOST=127.0.0.1:9000
  database rules:   demo-app-default-rtdb <- ./database.rules.json; another instance: every request is allowed (database.defaultAccess = open, default)
```

## Connect

`fireemu exec` sets `FIREBASE_DATABASE_EMULATOR_HOST` for the command it runs, and the Admin SDK reads it. Web and mobile clients connect explicitly:

```js
import { initializeApp } from 'firebase/app';
import { getDatabase, connectDatabaseEmulator } from 'firebase/database';

const app = initializeApp({ projectId: 'demo-app', databaseURL: 'https://demo-app-default-rtdb.firebaseio.com' });
const db = getDatabase(app);
connectDatabaseEmulator(db, '127.0.0.1', 9000);
```

A database instance is a namespace. Requests choose one with the `ns` query parameter or the first label of the host name, as on the official emulator. `demo-app-default-rtdb` is the default instance of the project `demo-app`: ID tokens are checked against that project, and against the daemon's project for an instance with any other name. A session reset and session snapshots cover `<project>` and `<project>-default-rtdb`.

## What is served

- The REST API (`.json` paths): reads, writes, updates, push ids, conditional requests with ETags, `shallow`, `print`, `format=export`, queries, and event streams (`Accept: text/event-stream`).
- The realtime protocol over WebSocket and over long polling (`forceLongPolling()`), with listens, queries, transactions and server values.
- `onDisconnect` writes (`set`, `update`, `remove`, `cancel`). They run when the connection ends, however it ends, as one update with their server values resolved at that moment. They do not run when Fireemu itself stops, as the official emulator does not run them when it stops, and a session reset drops those registered for the projects it resets.
- Security Rules (below), `/.settings/rules.json`, `/.inspect/databases.json`, and `disableTriggers` on writes.
- Export, import and session snapshots (below).

`tools/sdk-smoke-database` in the repository drives these through the pinned `firebase` and `firebase-admin` SDKs and compares the results with a recording of the official emulator.

## Security Rules

### Load rules

Name the rules file in `firebase.json`, as for the Firebase CLI. The single form loads one file into the default instance, `<project>-default-rtdb`:

```json
{
  "database": { "rules": "database.rules.json" }
}
```

The array form loads each entry into its `instance`, or into the instances of its deploy `target` from `.firebaserc`:

```json
{
  "database": [
    { "instance": "demo-app-default-rtdb", "rules": "database.rules.json" },
    { "target": "audit", "rules": "audit.rules.json" }
  ]
}
```

A rules file that does not load stops the start with the file, line and column, as firebase-tools stops. A changed file is loaded again while Fireemu runs; a change that does not load keeps the rules in force and prints why. `GET` and `PUT /.settings/rules.json?ns=<instance>` read and replace an instance's rules with an administrator credential, which is how `@firebase/rules-unit-testing` loads them.

Rules are evaluated as the official emulator evaluates them: `.read`, `.write`, `.validate` and `.indexOn`, with `auth`, `now`, `root`, `data`, `newData`, `query` and `$` variables, over REST, event streams and the realtime protocol. `onDisconnect` writes are checked when they are registered and again when they run, each on its own, so a denied one leaves the others. A rules change, a write that changes what a data-dependent `.read` allows, or a client signing in or out cancels the listens and event streams the rules no longer allow.

### Credentials

| Credential | `emulator` profile | `strict` profile (the default) |
|---|---|---|
| `Authorization: Bearer owner` (the Admin SDK against an emulator) | Administrator; rules do not apply | Administrator; rules do not apply |
| Any other `Authorization: Bearer` or `access_token` | Administrator, as on the official emulator (safe only because the listener is loopback) | Refused with 401 |
| `auth=<ID token>` signed by Fireemu's Auth | The user it names, its custom claims as members of `auth` | The user it names, when the token is for the instance's project |
| `auth=<unsigned ID token>` (`@firebase/rules-unit-testing`, `mockUserToken`) | The user its `sub` names, whatever project it names and with or without `aud`, as the official emulator reads it | The user it names when it has the `createMockUserToken` shape and the instance's project as audience, while `auth.allowUnsignedIdTokens` is `true` (the default; `false` under `productionExact`) |
| Any other `auth=` value | Anonymous | Refused with 401 |

`/.inspect/databases.json`, which `firebase emulators:export` reads, answers anyone under the `emulator` profile and only the `owner` credential under `strict` or with a locked database.

### An instance without rules

An instance with no rules file follows `database.defaultAccess`:

- `"open"` (the development default in both profiles): every request is allowed, as the official emulator serves a database without rules.
- `"locked"` (the `productionExact` default, `strict` profile only): only the `owner` credential reads and writes, as a new production database in locked mode admits only administrators. Other administrator tokens are then held to the rules too.

```toml
schemaVersion = 1
profile = "strict"

[database]
defaultAccess = "locked"
```

### Unit testing with `@firebase/rules-unit-testing`

`initializeTestEnvironment` loads the rules you pass through `/.settings/rules.json`, `authenticatedContext()` sends an unsigned mock token, and `withSecurityRulesDisabled()` and `clearDatabase()` are served:

```js
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { readFileSync } from 'node:fs';

const [host, port] = process.env.FIREBASE_DATABASE_EMULATOR_HOST.split(':');
const testEnv = await initializeTestEnvironment({
  projectId: 'demo-app',
  database: { host, port: Number(port), rules: readFileSync('database.rules.json', 'utf8') },
});
const alice = testEnv.authenticatedContext('alice').database();
await assertSucceeds(alice.ref('users/alice').set({ name: 'Alice' }));
await assertFails(alice.ref('users/bob').set({ name: 'Mallory' }));
await testEnv.cleanup();
```

Run it with `npx fireemu exec --only database -- node test.mjs`. To test production's refusal of unsigned tokens, set `auth.allowUnsignedIdTokens` to `false` or set [`productionExact`](../../guides/profiles/).

### Limits

- An expression nests at most 600 levels; `&&`, `||` and `+` chains of any length count once. This is a local safety budget: the official emulator itself fails between 2,000 and 4,000 levels.
- A `matches()` call that exceeds the regular-expression engine's step or depth budget is an error, so the rule is false whether or not it is negated.
- A write's path is at most 768 bytes and its data at most 32 levels deep, as production documents.

## Differences from the official emulator

Every known difference refuses or denies where the official emulator allows, except the last one in this list. No known difference lets a request through that the official emulator denies.

### Regular expressions

The official emulator reads `matches()` patterns in a dialect of its own, an automaton grammar that is neither JavaScript's nor RE2's. Fireemu follows its grammar where it is recorded. For example, `a+?` means `(a+)?` (not a lazy repetition), `/a|q/` is searched as `.*a|q.*`, and under `i` an ASCII pattern folds case as there while the string being matched is left as it is. A construct whose meaning Fireemu does not reproduce yet is an error, so the rule is false whether or not it is negated:

| Construct | Example |
|---|---|
| `(?…)` groups | `/(?:a)/`, `/(?i)a/` |
| POSIX classes | `/[[:alpha:]]/` |
| `\W` and `\D`, anywhere | `/\W/`, `/[\D]/` |
| An escaped letter or digit other than `\d` and `\w` | `/\n/`, `/\x41/`, `/\1/` |
| An escaped backslash inside a class | `/[\\a]/` |
| An operator that starts an alternative | `/(|a)/`, `/^(a|*)$/` |
| The `i` flag with any character beyond ASCII in the pattern | `/^é$/i`, `/[ａ-ｚ]/i` |

Patterns the official emulator refuses when the rules load, such as `\s`, an unclosed class or group, or an unescaped `^` in the middle, are refused here with the same message.

### Other differences

- A lone escaped surrogate in a string literal (`'\uD83D'`) is refused when the rules load; the official emulator loads it.
- With no `auth`, `auth.uid == null` is an error here (the rule is false, negated or not); the official emulator reads it as `true`.
- A few rules both refuse are refused with another message or at another column.
- A pattern the official emulator cannot determinize ("could not determinize efficiently", a resource limit of its automaton library) is refused there when the rules load and loads here. Production's limit is not known.

## Export, import and snapshots

`emulators:export`, `--export-on-exit` and the Hub's export write `database_export/<instance>.json` for every instance that holds data or was imported, in the export format of `GET /.json?format=export` (priorities kept), with the `database` section of `firebase-export-metadata.json` that firebase-tools writes. The files are byte-identical to the Firebase CLI's for the same data, and each tool imports the other's export.

```sh
npx fireemu exec --only database --export-on-exit ./emulator-data -- npm test
npx fireemu exec --only database --import ./emulator-data -- npm test
```

```text
emulator-data/
  firebase-export-metadata.json
  database_export/
    demo-app-default-rtdb.json
```

`--import` writes each file as the `owner` credential with `disableTriggers=true`, as firebase-tools does, before the command starts. The file name, lowercased, is the instance. A file named after an invalid instance, or one the database would refuse (invalid JSON, an invalid key, data nested too deep), stops the start before any other product's data is installed. An export's database section is skipped, with a note, when the database is not selected.

Session snapshots and resets include the instances of the session's project. A restore is seen by open listeners and event streams, and drops the `onDisconnect` writes registered for those instances. In [test worlds](https://github.com/t-k/fireemu/blob/main/docs/test-worlds.md), select `database` in `services`; `world.endpoints.database` and `FIREBASE_DATABASE_EMULATOR_HOST` route to it, and its data survives export, import and reset.

## Not supported yet

- Rules coverage reports (the official emulator's `/.inspect/coverage`).
- Realtime Database triggers for Cloud Functions.
- A view in the Emulator UI.
- Android, Apple, Unity and the Java and Python Admin SDKs are outside the current Node and Web scope.

## Provisional behavior

Where production has not been observed, Fireemu follows the official emulator, and that behavior may change once production is observed. This covers number forms such as `1.0`, a write of an equal value, priorities, refusal texts, long-polling framing, how `onDisconnect` writes combine, the credentials of each profile, the regular-expression dialect, where the official emulator refuses a key of 768 bytes in a write's body but accepts it in the path, and the patterns it cannot determinize.
