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

See the [Functions support inventory](https://github.com/t-k/fireemu/blob/main/docs/functions-export-inventory.md) for support by trigger type and export.

| Trigger | v1 (`firebase-functions/v1`) | v2 (`firebase-functions/v2/*`) |
|---|---|---|
| HTTP and callable | `https.onRequest`, `https.onCall` | `onRequest`, `onCall`, `onCallGenkit` |
| Firestore | `firestore.document()` events | `onDocumentCreated`, `Updated`, `Deleted`, `Written`, and the `WithAuthContext` variants |
| Storage | `storage.object()` events | `onObjectFinalized`, `Deleted`, `MetadataUpdated`, `Archived` |
| Pub/Sub | `pubsub.topic().onPublish` | `onMessagePublished` |
| Scheduled | `pubsub.schedule()` | `onSchedule` |
| Task queues | `tasks.taskQueue().onDispatch` | `onTaskDispatched` |
| Authentication | `auth.user()` events, `beforeCreate`, `beforeSignIn` | `beforeUserCreated`, `beforeUserSignedIn`; `beforeEmailSent` under `strict` |
| Realtime Database | `database.ref()` and `database.instance().ref()` `onCreate`, `onUpdate`, `onDelete`, `onWrite` | `onValueCreated`, `Updated`, `Deleted`, `Written` |
| Eventarc and alerts | | `onCustomEventPublished`, `onAlertPublished` |

Local Realtime Database instances are in `us-central1`, so a 2nd-gen database trigger in another region does not fire, and a warning at load says so. [Local Functions triggers](../realtime-database/#local-functions-triggers) describes how a write and its events are admitted. Production observations cover a fixed sequence of administrator and unauthenticated writes; end-user writes and other delivery cases remain unverified.

Storage archive events fire only for a bucket whose versioning was turned on (`PATCH /storage/v1/b/{bucket}` with `{"versioning":{"enabled":true}}`), and their shape is unrecorded.

Triggers for products Fireemu does not deliver events for, such as Remote Config (deferred) and Data Connect (deferred), cannot run. By default discovery refuses a codebase that exports one; set `functions.unservedTriggers` to `"report"` to report each one and load the rest. The Functions page of the [Emulator UI](../../guides/ui/) and `GET /v1/sessions/default/functions` on the control API list every ignored export with the reason.

## Parameters and secrets

`defineString`, `defineInt`, `defineBoolean`, `defineFloat` and `defineList` resolve as a deploy resolves them: a value from `.env`, `.env.<projectId>` (or `.env.<alias>`) or `.env.local` wins, then the parameter's `default`. A parameter with neither a value nor a default refuses to start the codebase, naming the parameter and the files a value goes in, because `firebase deploy` stops for it in the same way. `.env.local` is applied by Fireemu and the official emulator but is never deployed, so a value that is only there is missing in production.

Secrets (`defineSecret`) come from `.secret.local` and reach only a function that declares them.

## Who can call a function

A function whose `invoker` is `"private"` or a list of service accounts, and every task-queue function, refuses a call without credentials on its public URL with 403, as Cloud Run refuses it before the function runs. Fireemu cannot check an identity token with Google, so a request that carries a bearer shaped like a Google-issued identity token (a JWT whose `iss` is `https://accounts.google.com`) is let in. Any other bearer is refused with 401, including the Firebase Auth ID token that a signed-in client SDK sends: Cloud Run does not accept it either. Task dispatch, the Emulator UI and the control API (`POST /v1/sessions/default/functions/{name}:run`, the console's invoke and enqueue) are not calls to the public URL; the UI and the control API act as the project owner. `ingressSettings` is recorded but not enforced. The `emulator` profile serves every function to every caller, as the official emulator does.

## Task queues

A task enqueued with a `scheduleTime` (or `scheduleDelaySeconds`) waits until then under `strict`, as it does in Cloud Tasks, and a `scheduleTime` that is not RFC 3339, or more than 30 days ahead, is refused with 400. The `emulator` profile dispatches at once, as the official emulator does. To test a delayed task without waiting, set `functions.clock.tasks` to `"virtual"` and move the clock (see [Time and scheduled functions](../../guides/time/)), or release the waiting tasks: the Functions page of the Emulator UI lists them with their due time and a **Run now** button, and the control API takes `POST /v1/sessions/default/functions/{queue}:run` (all waiting tasks) or the same with `{"task": "<task id>"}` (one task). Rate limits and concurrency still apply to a released task.

For a test that only needs current work to settle, send `POST /v1/sessions/default:awaitIdle` with `{ "scope": "runnable" }` (v0.26.0+). Future schedules and retry backoff do not block this scope; due tasks waiting on rate/concurrency and active HTTP requests still do. Omitting the scope waits for all work. See [waiting for runnable work](../../guides/time/#wait-for-runnable-work).

## Exports that never run

An export Fireemu cannot serve (a function whose options fail to resolve, or an event type it does not recognise) is skipped, and each one is a `warning:` on standard error at start, followed by a summary line. A function that production would deploy and run never runs here, so a test that asserts "no side effect" passes for the wrong reason; read the warnings. `functions.unservedTriggers` still refuses the products Fireemu does not serve.

## Serving a fixed list of functions (`functions.manifest`)

`functions.manifest` names a JSON file that replaces what discovery reports as the served set. It holds a `functions` array; each entry has a `name` and a `trigger` whose `type` is one of `http`, `firestore`, `database`, `storage`, `pubsub`, `schedule`, `auth`, `blockingAuth`, `tasks` or `eventarc`, with optional `region`, `generation`, `entryPoint`, `timeoutSeconds`, `retry` and `concurrency`. Fireemu still loads and discovers your codebase, so the runner starts and the code is checked, but the functions it serves, their trigger types and their options are the file's: an export the file leaves out is not served, and a function is served with the trigger the file gives it.

```json
{
  "schemaVersion": 1,
  "profile": "strict",
  "functions": { "manifest": "manifest.json" }
}
```

```json
{
  "functions": [
    { "name": "hello", "trigger": { "type": "http", "callable": false } },
    {
      "name": "ping",
      "trigger": {
        "type": "http",
        "callable": true,
        "enforceAppCheck": false,
        "consumeAppCheckToken": "disabled"
      }
    }
  ]
}
```

For a codebase that exports `hello` (`onRequest`), `ping` (`onCall`) and `worker` (`onTaskDispatched`), this starts with `functions loaded: hello, ping`; `worker` is not served. Without the key, all three are.

- The path is read from the working directory, whichever directory the configuration file is in (as the other file settings in a canonical file are; see [Configuration files](../../guides/configuration/)). A file that is missing, is not JSON or holds an invalid entry stops startup, naming the path or the function (`functions manifest manifest.json: No such file or directory`, `manifest: function "hello": unsupported trigger type "carrierpigeon"`). Under `strict`, a declaration production refuses is refused here too.
- It applies to one codebase. A run that loads several refuses to start (`functions.manifest replaces discovery for one codebase, and this run loads 2 (a, b); name the one to load with --only functions:<codebase> or drop functions.manifest`).
- The file cannot change what the code is. Blocking Auth functions in the file must match the ones discovery found, or startup is refused (`... invents Blocking Auth hook ... it must match codebase discovery`).
- While [App Check](../app-check/) is active (the default under `strict`; `appCheck.enabled: true` under `emulator`; not when `appCheck.enabled` is `false`), the file also may not change how a callable is treated. These are refused at startup:
  - a callable listed with `"callable": false`, or an `onRequest` function listed with `"callable": true`;
  - a callable listed as a task queue, a blocking function or an event trigger (`... declares "ping" as a non-HTTP function, but the codebase declares it callable ...`, which says to list it as an http function with `callable: true` and the App Check options the code declares, remove it from the file, or export it with `onTaskDispatched` if it is meant to be a task queue);
  - a callable whose `enforceAppCheck` or `consumeAppCheckToken` differs from the code;
  - an HTTP function the codebase does not export.

  With App Check off, these checks do not run; only the Blocking Auth match above applies.

## Scheduled functions

Starting with v0.27.0, publishing a message to a first-generation schedule's `firebase-schedule-<function>-<region>` topic under `strict` also invokes the handler, preserving the original Pub/Sub data, attributes, ordering key and message ID. Normal scheduled occurrences and manual runs still invoke it once.

A schedule runs on Fireemu's virtual clock, not on real time. Set a start time with `daemon.clockStart` and move the clock to make occurrences due, or run a scheduled function immediately from the UI. See [Time and scheduled functions](../../guides/time/).

## App Check in callables

`enforceAppCheck` on callable functions works with no configuration: get a token from the debug-token exchange with any UUIDv4 and send it in `X-Firebase-AppCheck`. A call without a token, or with a malformed one, is refused with 401. `consumeAppCheckToken` is honored when App Check is enabled. See [App Check](../app-check/).

## Runner output

Function logs and runner standard error are forwarded to the local logs. If the runner exits before its startup handshake, diagnostics also include its exit status, captured standard error and a bounded tail of standard output. Application-written output is not automatically scrubbed of arbitrary secrets; avoid printing credentials or dumping the environment in function code.

## Debugging

Run the Functions runner under the Node inspector with `--inspect-functions`:

```sh
npx fireemu up --inspect-functions 9229
```

## Production verification

HTTP and callable functions, event triggers and scheduled functions are verified against recordings from deployed functions. See the [compatibility tables](../../compatibility/#production-verification).
