---
title: Cloud Firestore
description: Run Cloud Firestore locally with production's query, index, transaction and Security Rules behavior.
---

Fireemu serves Cloud Firestore over gRPC, REST and the WebChannel transport the Web SDK uses, with Firestore Security Rules. Connect to it at `127.0.0.1:8080` (see [Connect your app](../../getting-started/connect/)).

## Editions and API modes

Select the database edition and API mode in `fireemu.json`. `fireemu init` writes the Standard edition with the Native API:

```json
{
  "schemaVersion": 1,
  "firestore": { "edition": "standard", "apiMode": "native" }
}
```

`edition` accepts `standard` and `enterprise`. The Enterprise Pipeline API supports a limited subset of read operations; see [Limitations](../../compatibility/limitations/).

## Composite indexes

Production refuses a query whose composite index is not defined. The official emulator assumes every index exists, so a missing index is usually found only after deploying. Fireemu checks each query against the indexes declared in `firestore.indexes.json` (referenced from `firebase.json`), as production does.

| `firestore.missingIndexes` | Behavior |
|---|---|
| `refuse` (default) | The query is refused with `FAILED_PRECONDITION` and the console link, as production refuses it. |
| `report` | The query runs. Each missing index is reported once per database on standard error, with production's refusal text and the `firestore.indexes.json` entry to add. |

The `emulator` profile always runs the query, as the official emulator does.

### Checks on `firestore.indexes.json`

Under `strict`, Fireemu refuses at start-up (and keeps the previous indexes when the file changes while it runs) what `firebase deploy` refuses, and the message names the entry:

- A composite index with a single field, such as `indexes[3]` with only `{"fieldPath": "n", "order": "ASCENDING"}`. Production answers "this index is not necessary, configure using single field index controls". Declare it under `fieldOverrides` instead, which is also how a collection-group query on one field is enabled. `(field, __name__ DESC)`, `(__name__ DESC)` and a single vector field are accepted, as production accepts them.
- An entry without a `fields` array, which is what a misspelled key such as `feilds` looks like.
- A `fieldOverrides` entry without an `indexes` array. A TTL-only override needs `"indexes": []`.
- A `fieldOverrides` index that has only a `vectorConfig`: each override index needs exactly one of `order` and `arrayConfig`. Declare a single vector field as a composite index instead, as production does.

A missing or empty `queryScope` is read as `COLLECTION`, and the older `collectionId` and field `mode` keys are read as `collectionGroup` and `order` / `arrayConfig`, as `firebase deploy` reads them. The limits of at most 200 composite indexes, 100 fields per index and one array field per index apply under both profiles. The Admin API's `indexes.create` applies the same checks, and counts the indexes of the file and the ones created at run time together against the 200.

The `emulator` profile loads the file as before, because the official emulator never reads it.

## Query limits

Under the `strict` profile, the Standard edition query limits are enforced as production enforces them. Setting `firestore.enforceLimits` to `false` lets queries pass that production refuses, so leave it on unless you have a specific reason. Under `strict` the key switches only these query limits (at most 30 disjunctions, 10 `in` values, and so on): the limits on writes, transactions and indexes, and the wire shapes of the REST and WebChannel surfaces, stay production's. Under the `emulator` profile, `true` also asks for those production limits.

## Listen streams

Production ends an end user's native gRPC `Listen` stream with `INTERNAL` an hour after it opened. By default Fireemu keeps the stream open however long it is held (`firestore.listenStreamLifetime: "unlimited"`). To test a client's reconnect, either set it to `"oneHour"` (the default with `productionExact`), or call `POST /v1/firestore/listen:expire` on the control API to end every held end-user stream at once with production's status.

## Transactions and history

Like production, Fireemu keeps every version of a document written in the last hour, so a `read_time` read, a read-only transaction or a resumed listener can see it. Transactions lock what they read, as production does.

A test that updates the same documents many times therefore holds many versions in memory. These local limits, which production does not have, bound it:

- Each database retains at most 1 GiB of logical history bytes and 1,000,000 versions, each session 1 GiB and 1,000,000 versions, and the daemon 4 GiB and 4,000,000 versions.
- On a pinned clock (`daemon.clockStart`), a database keeps at most 1,024 versions of any one document.
- A commit that would cross a limit is refused whole with `RESOURCE_EXHAUSTED` and the message `Firestore retained history capacity is exhausted`.

To use less memory, lower the limits in `firestore.history`:

```json
{
  "schemaVersion": 1,
  "firestore": {
    "edition": "standard",
    "apiMode": "native",
    "history": { "maxVersionsPerPath": 16, "maxBytes": 268435456 }
  }
}
```

- `maxVersionsPerPath` (1 to 1,000,000) sets the most versions of one document a database keeps.
- `maxBytes` (1 MiB to 1 GiB) lowers the logical history bytes one database retains.

Once any document has more versions than the cap, the database keeps no snapshot older than that document's oldest kept version. An older `read_time` read is then refused with `FAILED_PRECONDITION`, a transaction open on an older snapshot fails with `ABORTED`, and a listener resuming from an older point is sent the full result again. Client SDKs retry `ABORTED` transactions, so avoid very small caps: choose a cap above the number of times any document is updated while your longest transaction is open.

`fireemu doctor --connect <control URL>` reports the retained versions and bytes of a running daemon.

## Security Rules

Rules are read from the `firestore.rules` file named in `firebase.json`, or from `rules.source` in `fireemu.json`. Under `strict`, a project without rules refuses every client request, as a production project without a rules release does. See [Security Rules](../../guides/security-rules/).

## Named databases

Declare each named database in the `firestore` array of `firebase.json`, with the `rules` and `indexes` files it uses, or create it through the Admin API. Under `strict` a request to a database that is neither declared nor created gets `NOT_FOUND`, as in production, and a declared database id must be one production could create (4 to 63 characters of `[a-z0-9-]`, starting with a letter), or Fireemu does not start.

Production governs a database only by its own rules release. So a database created at run time has no Security Rules, and refuses every client request, until you set some for it; the `(default)` database's rules do not apply to it. Declare the database in `firebase.json` with its `rules` file, or load them at run time:

```
PUT /emulator/v1/projects/{project}/databases/{database}:securityRules
{"rules": {"files": [{"name": "firestore.rules", "content": "..."}]}}
```

This is the route `PUT /emulator/v1/projects/{project}:securityRules` uses for the `(default)` database, with the same body and answers. The rules set this way last until the database is deleted; they are not part of a snapshot. The `emulator` profile keeps the official emulator's behavior: a database that has no rules of its own is served by the `(default)` database's rules (rules loaded for it with the route above apply to it).

## Production verification

Writes and limits, queries and indexes, transactions, real-time listeners, Security Rules and database administration are verified against recordings from real Firestore. See the [compatibility tables](../../compatibility/#production-verification).
