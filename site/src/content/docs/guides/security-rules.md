---
title: Security Rules
description: Load Firestore, Storage and Realtime Database Security Rules, and find out why a request was denied.
---

## Load rules

Name the rules files in `firebase.json`, as for the Firebase CLI:

```json
{
  "firestore": { "rules": "firestore.rules", "indexes": "firestore.indexes.json" },
  "storage": { "rules": "storage.rules" }
}
```

or in `fireemu.toml` (`rules.source` for Firestore, `storage.rules` for Storage). The startup output has a `firestore rules:` and a `storage rules:` line that say whether rules are loaded.

Realtime Database rules load from the `database` section of `firebase.json`, a single file for the default instance or one per instance or deploy target; the startup output's `database rules:` line names each file and its instance. See [Realtime Database](../../products/realtime-database/#security-rules) for the credentials each profile accepts, what an instance without rules allows, and the regular-expression differences from the official emulator.

`@firebase/rules-unit-testing` can also load rules at run time: `initializeTestEnvironment` sends the `firestore.rules` and `storage.rules` you pass to the emulators, and `testEnv.clearFirestore()` is served.

## A project without rules

Under `strict`, a project without Security Rules behaves as a production project without a rules release:

- every client request to Firestore is refused with `PERMISSION_DENIED`;
- every end-user request to Storage is refused with production's 400 "bucket has not been set up" answer.

The Admin SDK and other owner credentials are not affected. The `emulator` profile allows every Firestore request, and every Storage request for a `demo-*` project, as the official emulator does.

Because these answers keep production's wording, the first refused request for each database and bucket also prints a warning to standard error that says no rules are loaded and how to load them.

## Why a request was denied

Production answers a denial with a short message (Firestore's `PERMISSION_DENIED` "Missing or insufficient permissions.", Storage's 403) that does not say which rule refused. Fireemu also prints each denial of an end-user request to standard error, with every `allow` condition the request evaluated and what it evaluated to:

```text
note: firestore: Security Rules denied get on "notes/n1" in "database (default)" (request.auth.uid "bob"): no allow statement evaluated to true; line 5:22 `request.auth.uid == resource.data.owner` was false
```

- Set `rules.denialLog` to `"off"` in `fireemu.toml` to silence these lines, for example in a suite that asserts many denials. The answer to the client is the same either way.
- When the UI is running, its Rules page lists the decided requests from the start of the run, with what every expression evaluated to. The control API serves the same trace at `GET /v1/sessions/default/rules/requests`.

## `get()` and `exists()` on a path that is not a document

`get()` and `exists()` take a path to a document of the database the request runs in. A path to a collection (`/databases/$(database)/documents/users`, an odd number of segments after `documents`), to another database (`/databases/other/documents/users/u1`) or without `documents` (`/databases/$(database)/users/u1`) names no document, so the call is an evaluation error. Like any Rules error, it makes the condition fail: the request is refused unless the other side of an `||` or `&&` decides the result (`exists(<such a path>) || true` allows; production's answer for such a mix was not recorded). `!exists(...)` and `get(...) == null` do not read the path as "missing" and allow; production refuses them, and so does the official emulator. A path to a document that does not exist stays a missing document: `exists()` is `false` and `get()` is `null`. A missing document id from a mistyped path is the usual cause, so the denial log's line `was an error` points at the call.

## Unit testing with mock tokens

`@firebase/rules-unit-testing`'s `authenticatedContext()` and the client SDKs' `mockUserToken` option send an unsigned mock ID token. Fireemu accepts it by default, also under `strict`, and builds `request.auth` from its claims as the official emulator does. Under `strict` only that exact token shape is accepted; every other token is verified, expiry included.

To test production's refusal of unsigned tokens, set `auth.allowUnsignedIdTokens` to `false` or set [`productionExact`](../profiles/).
