---
title: Cloud Functions
description: Run Cloud Functions for Firebase locally, with HTTP, callable, event, scheduled, task queue and blocking functions.
---

Fireemu loads the Functions codebases declared in `firebase.json` and runs them with Node.js. Running Functions requires `firebase-functions` v6 or v7 in the codebase. When a codebase is loaded, the Eventarc and Cloud Tasks emulators start with it.

```sh
# All codebases declared in firebase.json
npx fireemu up

# One codebase
npx fireemu up --only functions:<codebase>

# One directory, whatever firebase.json declares
npx fireemu up --functions ./functions
```

## Supported triggers

| Trigger | v1 (`firebase-functions/v1`) | v2 (`firebase-functions/v2/*`) |
|---|---|---|
| HTTP and callable | `https.onRequest`, `https.onCall` | `onRequest`, `onCall`, `onCallGenkit` |
| Firestore | `firestore.document()` events | `onDocumentCreated`, `Updated`, `Deleted`, `Written`, and the `WithAuthContext` variants |
| Storage | `storage.object()` events | `onObjectFinalized`, `Deleted`, `MetadataUpdated`, `Archived` |
| Pub/Sub | `pubsub.topic().onPublish` | `onMessagePublished` |
| Scheduled | `pubsub.schedule()` | `onSchedule` |
| Task queues | `tasks.taskQueue().onDispatch` | `onTaskDispatched` |
| Authentication | `auth.user()` events, `beforeCreate`, `beforeSignIn` | `beforeUserCreated`, `beforeUserSignedIn`; `beforeEmailSent` under `strict` |
| Eventarc and alerts | | `onCustomEventPublished`, `onAlertPublished` |

Storage archive events fire only for a bucket whose versioning was turned on (`PATCH /storage/v1/b/{bucket}` with `{"versioning":{"enabled":true}}`), and their shape is unrecorded.

Triggers for products Fireemu does not serve, such as Realtime Database (deferred), Remote Config (deferred) and Data Connect (deferred), cannot run. By default discovery refuses a codebase that exports one; set `functions.unservedTriggers` to `"report"` to report each one and load the rest. The Functions page of the [Emulator UI](../../guides/ui/) and `GET /v1/sessions/default/functions` on the control API list every ignored export with the reason.

## Scheduled functions

A schedule runs on Fireemu's virtual clock, not on real time. Set a start time with `daemon.clockStart` and move the clock to make occurrences due, or run a scheduled function immediately from the UI. See [Time and scheduled functions](../../guides/time/).

## App Check in callables

`enforceAppCheck` and `consumeAppCheckToken` on callable functions are honored when App Check is enabled. See [App Check](../app-check/).

## Debugging

Run the Functions runner under the Node inspector with `--inspect-functions`:

```sh
npx fireemu up --inspect-functions 9229
```

## Production verification

HTTP and callable functions, event triggers and scheduled functions are verified against recordings from deployed functions. See the [compatibility tables](../../compatibility/#production-verification).
