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

Realtime Database rules load from the `database` section of `firebase.json`: a single file for the default instance, or one per instance or deploy target. The startup output's `database rules:` line names each file and its instance. See [Realtime Database](../../products/realtime-database/#security-rules) for the credentials each profile accepts, what an instance without rules allows, and the differences from the official emulator.

- Comparison with the official emulator is limited to recorded cases.
- The listed unsupported syntax and evaluation cases are refused when rules load, or produce rule errors.
- The eight recorded patterns refused by the official emulator's determinization resource limit are also rejected when Fireemu loads rules, including in unevaluated expression branches. This does not establish complete regular-expression or production equivalence.

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
- The Rules page and `GET /v1/sessions/default/rules/requests` show the newest 100 traced Firestore decisions. By default tracing starts with the UI or the first control-API read; loading a new ruleset clears the history. This is a debugging view, not a complete request log.
- To keep the history from daemon start, set `rules.denialHistory.enabled` to `true` in `fireemu.toml`. The `retention` setting (1 to 10000, default 100) sets how many decisions are kept. Each ruleset load restarts the history with the same retention. The route then also reports `historyEnabled`, `retention` and `dropped`, the number of decisions that fell out of the window since the last load. A value outside 1 to 10000 is refused at startup with the range in the message. The option is off by default, so the default behaviour does not change.

Firestore and Storage Rules diagnostics keep at most 64 distinct values per expression. String values and error messages are cut at a character boundary within 1,024 UTF-8 bytes. Firestore coverage JSON/HTML and control request traces mark cut values with `truncated: true`; omitted observations add `valuesOmitted` and `valuesCountMayBeLower: true`. Displayed counts can therefore be lower than the actual count for a value. These bounds affect diagnostics only, not allow/deny decisions.

## Unit testing with mock tokens

`@firebase/rules-unit-testing`'s `authenticatedContext()` and the client SDKs' `mockUserToken` option send an unsigned mock ID token. Fireemu accepts it by default, also under `strict`, and builds `request.auth` from its claims as the official emulator does. Under `strict` only that exact token shape is accepted; every other token is verified, expiry included.

To test production's refusal of unsigned tokens, set `auth.allowUnsignedIdTokens` to `false` or set [`productionExact`](../profiles/).
## Rules language details

These sections describe edge cases of how Fireemu evaluates Rules.

### `get()` and `exists()` on a path that is not a document

`get()` and `exists()` take a path to a document of the database the request runs in. A path to a collection (`/databases/$(database)/documents/users`, an odd number of segments after `documents`), to another database (`/databases/other/documents/users/u1`) or without `documents` (`/databases/$(database)/users/u1`) names no document, so the call is an evaluation error. Like any Rules error, it makes the condition fail: the request is refused unless the other side of an `||` or `&&` decides the result (`exists(<such a path>) || true` allows; production's answer for such a mix was not recorded). `!exists(...)` and `get(...) == null` do not read the path as "missing" and allow; production refuses them, and so does the official emulator. A path to a document that does not exist stays a missing document: `exists()` is `false` and `get()` is `null`. A missing document id from a mistyped path is the usual cause, so the denial log's line `was an error` points at the call.

### Queries and the stored documents

A Firestore query is authorized from its filters, not from the documents it would return, as in production. One exception: a query branch with a single `documentId() ==` filter is decided by that document as stored, whatever other filters, limit, offset or cursor it has, as production and the official emulator decide it. In the proof, `resource.data` holds exactly the fields the query filters on or orders by, so `keys()`, `size()`, `in` and `get(key, default)` answer from those fields only.

An `OR` query that mixes a branch naming one document with a branch naming none differs by profile. The `emulator` profile authorizes it branch by branch, as the official emulator does. The `strict` profile proves every branch from its filters, because production answered that query with a missing-index error and its Rules answer is not recorded.

### Strings in rules

Firestore and Storage Rules index and measure a string by UTF-16 code unit, as production does: `"é🔥x".size()` is 4 and `"é🔥x"[3] == "x"`. `lower()` and `upper()` change ASCII letters only, and strings are never normalized. Half of a surrogate pair differs by profile. Under `strict` it is a fragment that equals only itself, and a `split()`, `replace()` or `matches()` pattern that holds a lone surrogate fails the rule, as production answered. The `emulator` profile keeps the lone unit, as the official emulator does. Regular expressions still treat a supplementary character as one character.
