---
title: Cloud Functions
description: Run Cloud Functions for Firebase locally, with HTTP, callable, event, scheduled, task queue and blocking functions.
---

Fireemu loads the Functions codebases declared in `firebase.json` and runs them with Node.js. Running Functions requires `firebase-functions` v6 or v7 in the codebase. Python codebases (`python310` to `python314`) run too; see [Python codebases](#python-codebases). When a codebase is loaded, the Eventarc and Cloud Tasks emulators start with it.

```sh
# All codebases declared in firebase.json
npx fireemu up

# One codebase
npx fireemu up --only functions:<codebase>

# One directory, whatever firebase.json declares
npx fireemu up --functions ./functions
```

## Python codebases

A codebase is Python when its `runtime` in `firebase.json` is `python310`, `python311`, `python312`, `python313` or `python314`, or when it declares no `runtime`, has no `package.json` and has a `requirements.txt` (the order the Firebase CLI uses). Fireemu runs it with the interpreter of the codebase's own virtual environment, always `<source>/venv/bin/python`, and never creates the environment or installs packages:

```sh
cd functions
python3.12 -m venv venv
venv/bin/pip install -r requirements.txt   # includes firebase-functions
npx fireemu up
```

Before anything starts, fireemu checks the environment and stops with the Firebase CLI's message when `venv` is missing or `firebase_functions` cannot be imported, and with a message naming both versions when the interpreter's Python differs from the declared `runtime`. The tested SDK is `firebase-functions` 0.6.0. Linux and macOS only.

This release serves HTTP (`https_fn.on_request`), callable (`https_fn.on_call`), Firestore document triggers (`on_document_created`, `updated`, `deleted`, `written` and the `_with_auth_context` variants), Pub/Sub (`pubsub_fn.on_message_published`), Cloud Storage (`storage_fn.on_object_finalized`, `deleted`, `archived`, `metadata_updated`), Eventarc custom events (`eventarc_fn.on_custom_event_published`) and Realtime Database (`db_fn.on_value_created`, `updated`, `deleted`, `written`) triggers. It also serves scheduled functions (`scheduler_fn.on_schedule`), task queue functions (`tasks_fn.on_task_dispatched`) and Auth blocking functions (`identity_fn.before_user_created`, `before_user_signed_in`). A callable sees the user of the Auth emulator. A trigger for a product fireemu does not serve is reported when the codebase loads and never runs; discovery refuses such a codebase unless `functions.unservedTriggers` is `"report"`, as for the products listed below.

Where it differs from production and from the Firebase CLI:

- One Python process serves the whole codebase, where production gives each function its own instance and the CLI its own process. Module-level state is shared between functions, the `@init` callback runs once per process, on the first call of any function, and `FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE` and `K_SERVICE` name the function that started most recently when calls overlap.
- Time is real time. Python code is not moved onto the virtual clock, so `datetime.now()` ignores `daemon.clock` settings; a configuration that asks for a virtual date for the Functions runner is refused for a Python codebase.
- Source changes are not reloaded; restart fireemu.
- A scheduled function is called as Cloud Scheduler calls it, through the SDK's request wrapper: a handler that raises is logged by the SDK and fails the attempt, and the schedule time the handler sees is written in Los Angeles time in the strict profile and in UTC in the emulator profile (the same instant).
- Secrets from `.secret.local` are in the environment only while a function that declares them runs: a function with a secret runs alone, in arrival order, and every function without one runs with all local secrets hidden, beside other such functions. Functions without secrets are never held up by each other.
- Python Storage and Eventarc handlers parse the event `time` with a fractional-second pattern, so production's SDK fails on a whole-second time. The strict profile delivers the time as production does; the emulator profile adds `.000` to a whole-second time, as the official emulator's events always carry milliseconds.
- `--inspect-functions` is ignored with a warning, as the Firebase CLI does.
- App Check for a Python callable is checked by the Python SDK itself, as in production: it verifies the `X-Firebase-AppCheck` token with the Admin SDK, and Fireemu points that check at the App Check emulator's keys, so only a token the emulator signed is accepted and an `enforce_app_check=True` callable answers 401 to every other call. This works when the run has an App Check emulator, which the strict profile starts with Functions. Without one the header is removed before the function and no callable sees a token. Limits: the SDK checks the token's times against real time while the emulator signs them on its own clock, so a token minted after you moved the clock ahead of real time is refused as not yet valid; limited-use token consumption (`verify_token(..., consume=True)`) is refused; and a configuration that turns App Check on explicitly (`appCheck` in the configuration file) refuses to start with a Python codebase.

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

  With App Check off, these checks do not run; only the Blocking Auth match above applies. No override reaches the callable wrapper that a mislabelled entry points at: the runner is not told to skip token verification (only the App Check protocol does that), and the daemon strips the emulator-internal auth override fields (`x-callable-context-auth`, `x-original-auth`) from every request it forwards, task dispatch included. The wrapper's token check is the Auth emulator's, exactly as for an `onTaskDispatched` function reached by a task; under `strict` a task sent to such a queue, or a request to a callable that the file lists as an `onRequest` function (`"callable": false`), also passes the Bearer check a callable request passes (a preflight and a request with no credential do not), so a Bearer that is not one of the project's users is answered 401 before the code runs. For a task that is a failed dispatch, retried under the queue's retry policy until it gives up; each refusal prints a line naming the function (never the credential), and startup prints a warning naming it too. The 401 HTML body for a callable deployed as an `onRequest` function is provisional: that deployment shape has not been observed in production. The official emulator does not compare a `functions.yaml` with the code either.

## Scheduled functions

Starting with v0.27.0, publishing a message to a first-generation schedule's `firebase-schedule-<function>-<region>` topic under `strict` also invokes the handler, preserving the original Pub/Sub data, attributes, ordering key and message ID. Normal scheduled occurrences and manual runs still invoke it once.

A schedule runs on Fireemu's virtual clock. Unless you pin a start time with `daemon.clockStart`, that clock follows real time, so occurrences come due as time passes; with a pinned start it stands still, and you move the clock to make occurrences due (or run a scheduled function immediately from the UI). See [Time and scheduled functions](../../guides/time/).

## App Check in callables

`enforceAppCheck` on callable functions works with no configuration: get a token from the debug-token exchange with any UUIDv4 and send it in `X-Firebase-AppCheck`. A call without a token, or with a malformed one, is refused with 401. `consumeAppCheckToken` is honored when App Check is enabled. See [App Check](../app-check/).

Under the `strict` profile the daemon also verifies a callable's `Authorization` bearer before it forwards the call, for Node and Python codebases alike. A request that carries more than one `Authorization` header is refused with 401 before anything is forwarded.

## Runner output

Function logs and runner standard error are forwarded to the local logs. If the runner exits before its startup handshake, diagnostics also include its exit status, captured standard error and a bounded tail of standard output. Application-written output is not automatically scrubbed of arbitrary secrets; avoid printing credentials or dumping the environment in function code.

## Debugging

Run the Functions runner under the Node inspector with `--inspect-functions`:

```sh
npx fireemu up --inspect-functions 9229
```

## Production verification

HTTP and callable functions, event triggers and scheduled functions are verified against recordings from deployed functions. See the [compatibility tables](../../compatibility/#production-verification).
