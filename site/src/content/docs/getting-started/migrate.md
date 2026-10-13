---
title: Migrate from the Local Emulator Suite
description: Move a project from firebase emulators:exec to Fireemu.
---

Fireemu reads your existing `firebase.json`, serves the same ports, and accepts the official command names, so most projects move by changing one command.

## Steps

1. Install Fireemu and create `fireemu.json` that references your `firebase.json`:

   ```sh
   npm install --save-dev fireemu
   npx fireemu init --firebase-json firebase.json
   ```

   Keep `"profile": "strict"`, the default.

2. Replace the commands:

   | Before | After |
   |---|---|
   | `firebase emulators:exec "npm test"` | `fireemu exec -- npm test` |
   | `firebase emulators:start` | `fireemu up` |

   `fireemu emulators:exec` and `fireemu emulators:start` also work, and `exec` accepts the official quoted-script form.

3. Run your tests.

## When a test fails under `strict`

A test that passed on the official emulator but fails under `strict` usually shows behavior your application would also meet in production. Fix the test or the application, or relax only the specific setting below, rather than switching the whole profile to `emulator`.

- **Unsigned emulator ID tokens.** `@firebase/rules-unit-testing`'s `authenticatedContext()` and the client SDK's `mockUserToken` work under `strict` by default. Set `auth.allowUnsignedIdTokens` to `false` to test production's refusal of them.
- **Named databases.** Declare each named database in the `firestore` array of `firebase.json`, with its `rules` and `indexes` files, or create it through the Admin API, as production needs it created. A database created at run time has no Security Rules until you load some for it (see [Firestore](../../products/firestore/#named-databases)).
- **Composite indexes.** Queries are checked against your declared indexes, as production checks them. Declare the index a query needs in `firestore.indexes.json`, referenced from `firebase.json`. A query whose index is missing is refused with `FAILED_PRECONDITION` and a link to the index, as in production. A composite index with a single field is refused when the file loads, as `firebase deploy` refuses it: use `fieldOverrides`. To keep running such queries while you add the indexes, set `firestore.missingIndexes` to `"report"`: the query runs and the missing index is reported on standard error.
- **Settings that mirror your production project.** Set them to match it instead of switching the profile:

| Setting | What it does under `strict` |
|---|---|
| `auth.improvedEmailPrivacy` | Email enumeration protection, on for a new production project. Set `false` only if your production project turned it off; sign-ins then answer `EMAIL_NOT_FOUND` and `INVALID_PASSWORD` as the official Auth emulator does. |
| `auth.mfa` | Your project's multi-factor configuration. `strict` starts with multi-factor off, as a new production project does. See [Authentication](../../products/auth/#multi-factor-authentication). |
| `firestore.enforceLimits` | Production always enforces the Standard edition query limits. `false` lets queries pass that production refuses, so leave it on unless you have a specific reason. It switches only the query limits. |

## Differences from the official CLI

- A failed `--export-on-exit` makes the run exit 1 when the command succeeded. The official CLI only warns and exits 0; Fireemu differs so that a CI job that depends on the saved data cannot pass without it.
- On Unix, a discovered `fireemu.json` or `firebase.json` is loaded only when its owner is trusted. See [Configuration files](../../guides/configuration/#file-ownership-checks).
- Under `strict`, a project without Security Rules behaves as a production project without a rules release: client requests are refused. See [Security Rules](../../guides/security-rules/).
