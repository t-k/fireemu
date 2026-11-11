---
title: Cloud Functions
description: Run Cloud Functions for Firebase locally, with HTTP, callable, event, scheduled, task queue and blocking functions.
---

Fireemu loads the Functions codebases declared in `firebase.json` and runs them with Node.js. Running Functions requires `firebase-functions` v6 or v7 in the codebase. When a codebase is loaded, the Eventarc and Cloud Tasks emulators start with it. Python codebases (`python310` to `python314`) run too; see [Cloud Functions (Python)](../functions-python/). Unless a section says otherwise, this page describes Node.js codebases.

```sh
# Only Functions (with Eventarc and Cloud Tasks); add the services your functions use,
# for example --only functions,firestore,auth
npx fireemu up --only functions

# All codebases declared in firebase.json, with the default services
npx fireemu up

# One codebase
npx fireemu up --only functions:<codebase>

# One directory, whatever firebase.json declares
npx fireemu up --functions ./functions
```

Functions listens on `127.0.0.1:5001` by default (`--functions-port` or `firebase.json` changes it). Point the Web SDK at it:

```js
import { getFunctions, connectFunctionsEmulator } from 'firebase/functions';
connectFunctionsEmulator(getFunctions(app), '127.0.0.1', 5001);
```

Under `fireemu exec`, `FIREEMU_FUNCTIONS_HOST` holds the `host:port` for your command (see [Environment variables](../../reference/environment-variables/)).

## Supported triggers

These are the Node.js `firebase-functions` exports. See the [Functions support inventory](https://github.com/fireemu/fireemu/blob/main/docs/functions-export-inventory.md) for support by trigger type and export.

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

Production observations of Realtime Database triggers cover fixed administrator and unauthenticated sequences, plus 12 writes by an email/password user over REST and the web SDK, including ancestor and multi-path writes and redelivery after a failed invocation. Delivery timing, other providers and unrecorded write or handler shapes remain unverified. [Local Functions triggers](../realtime-database/#local-functions-triggers) describes how a write and its events are admitted.

:::caution[Trigger caveats]
- **Realtime Database, 2nd generation.** Local Realtime Database instances are in `us-central1`, so a 2nd-gen database trigger in another region does not fire, and a warning at load says so.
- **Products Fireemu does not deliver events for.** Triggers for products such as Data Connect (deferred) cannot run. By default discovery refuses a codebase that exports one (`functions.unservedTriggers = "refuse"`); set it to `"report"` to report each one and load the rest. The Functions page of the [Emulator UI](../../guides/ui/) and `GET /v1/sessions/default/functions` on the control API list every ignored export with the reason.
- **Remote Config.** Handlers run only through the local injection action, and its production event shape is unobserved.
- **Storage archive events.** They fire only for a bucket whose versioning was turned on (`PATCH /storage/v1/b/{bucket}` with `{"versioning":{"enabled":true}}`), and their shape is unrecorded.
- **`beforeEmailSent`.** It runs under `strict` only.
:::

## Parameters and secrets

`defineString`, `defineInt`, `defineBoolean`, `defineFloat` and `defineList` resolve as a deploy resolves them. Files are applied in the order below, a later file overriding an earlier one, and then the parameter's `default` applies. A parameter with neither a value nor a default refuses to start the codebase, naming the parameter and the files a value goes in, because `firebase deploy` stops for it in the same way. Secrets (`defineSecret`) come from `.secret.local` and reach only a function that declares them.

| File (in the codebase directory) | Holds | Precedence | Deployed |
|---|---|---|---|
| `.env` | Parameter values | Lowest | Yes, as `firebase deploy` reads it |
| `.env.<projectId>` (or `.env.<alias>`) | Values for one project | Over `.env` | Yes, when you deploy that project |
| `.env.local` | Values for local runs | Highest | Never: a value that is only here is missing in production. Applied by Fireemu and the official emulator |
| `.secret.local` | `defineSecret` values | The only source of secrets here | Never: a deploy needs the secret in Secret Manager |
| `default` in `defineString` and the others | A fallback | Below every file | In the code |

- Having both `.env.<projectId>` and `.env.<alias>` stops startup, as `firebase deploy` does.
- Fireemu never contacts Secret Manager. A secret a function declares but `.secret.local` lacks reads as the empty string, and a startup warning names the secret and the functions.
- `.runtimeconfig.json` is passed to the code as `CLOUD_RUNTIME_CONFIG` for a codebase that reads it. `firebase-functions` v7 has removed `functions.config()`, so a v7 codebase does not read it.

## Who can call a function

A function whose `invoker` is `"private"` or a list of service accounts, and every task-queue function, refuses a call without credentials on its public URL with 403, as Cloud Run refuses it before the function runs. Fireemu cannot check an identity token with Google, so a request that carries a bearer shaped like a Google-issued identity token (a JWT whose `iss` is `https://accounts.google.com`) is let in. Any other bearer is refused with 401, including the Firebase Auth ID token that a signed-in client SDK sends: Cloud Run does not accept it either. Task dispatch, the Emulator UI and the control API (`POST /v1/sessions/default/functions/{name}:run`, the console's invoke and enqueue) are not calls to the public URL; the UI and the control API act as the project owner. `ingressSettings` is recorded but not enforced. The `emulator` profile serves every function to every caller, as the official emulator does.

## Task queues

A task enqueued with a `scheduleTime` (or `scheduleDelaySeconds`) waits until then under `strict`, as it does in Cloud Tasks, and a `scheduleTime` that is not RFC 3339, or more than 30 days ahead, is refused with 400. The `emulator` profile dispatches at once, as the official emulator does. To test a delayed task without waiting, set `functions.clock.tasks` to `"virtual"` and move the clock (see [Time and scheduled functions](../../guides/time/)), or release the waiting tasks: the Functions page of the Emulator UI lists them with their due time and a **Run now** button, and the control API takes `POST /v1/sessions/default/functions/{queue}:run` (all waiting tasks) or the same with `{"task": "<task id>"}` (one task). Rate limits and concurrency still apply to a released task.

In both profiles, task dispatch preserves the enqueued JSON body's bytes, including member order and whitespace; non-JSON bodies are still refused. Under `strict`, `X-CloudTasks-QueueName` is the bare queue ID, `X-CloudTasks-TaskETA` is Unix seconds with six decimal places, and `User-Agent` is `Google-Cloud-Tasks`. Task-supplied headers cannot override that user agent or the `X-CloudTasks-*`, `X-Google-*` and `X-AppEngine-*` families. The `emulator` profile retains the official emulator's internal queue name and header overrides.

For a test that only needs current work to settle, send `POST /v1/sessions/default:awaitIdle` with `{ "scope": "runnable" }` (since v0.26.0). Future schedules and retry backoff do not block this scope; due tasks waiting on rate/concurrency and active HTTP requests still do. Omitting the scope waits for all work. See [waiting for runnable work](../../guides/test-worlds/#wait-for-runnable-work).

## Scheduled functions

A schedule runs on Fireemu's virtual clock. Unless you pin a start time with `daemon.clockStart`, that clock follows real time, so occurrences come due as time passes; with a pinned start it stands still, and you move the clock to make occurrences due. See [Time and scheduled functions](../../guides/time/).

### Run now

To run a scheduled function or release a delayed task without waiting:

| | Scheduled function | Task-queue function (tasks waiting for their `scheduleTime`) |
|---|---|---|
| Emulator UI, Functions page | Run it immediately, or advance the clock to its next occurrence | The waiting tasks, with their due time and a **Run now** button |
| Control API | `POST /v1/sessions/default/functions/{name}:run` | The same route releases all waiting tasks; with `{"task": "<task id>"}` it releases one (404 for an unknown id) |
| Virtual clock | Pin `daemon.clockStart`, or set `daemon.clock = "frozen"`, then `POST /v1/sessions/default/clock:advance` with `{"seconds": 86400}` (also `{"millis": n}`, `clock:advanceTo` and `clock:set`), or use the Runtime page | `functions.clock.tasks = "virtual"` with a pinned `daemon.clockStart`, then move the clock |

The control API is not on the UI port. Its address is the `control API:` line of the startup output: the Authentication port (9099 by default) when Authentication runs, another port otherwise. Under `fireemu exec` it is `$FIREEMU_CONTROL_URL`, with `Authorization: Bearer $FIREEMU_CONTROL_TOKEN` (the token is required only when `network.allowNonLoopbackHosts` is set). For example, with `fireemu up`:

```sh
curl -X POST http://127.0.0.1:9099/v1/sessions/default/functions/nightly:run
# {"enqueued":true,"function":"nightly"}
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -H 'content-type: application/json' -d '{"seconds": 86400}'
```

A name that is unknown or not scheduled answers `400 INVALID_ARGUMENT`. A manual run does not consume the next occurrence; see [Run a scheduled function now](../../guides/time/#run-a-scheduled-function-now).

Publishing a message to a first-generation schedule's `firebase-schedule-<function>-<region>` topic under `strict` also invokes the handler, preserving the original Pub/Sub data, attributes, ordering key and message ID. Normal scheduled occurrences and manual runs still invoke it once.

## App Check in callables

`enforceAppCheck` on callable functions works with no configuration: get a token from the debug-token exchange with any UUIDv4 and send it in `X-Firebase-AppCheck`. A call without a token, or with a malformed one, is refused with 401. Replay consumption is unavailable: a valid token on a Node callable with `consumeAppCheckToken: true` is refused with `APP_CHECK_REPLAY_UNSUPPORTED`. Python callables use the [verification and restrictions described for Python](../functions-python/#differences-from-production-and-the-firebase-cli). See [App Check](../app-check/).

Under the `strict` profile the daemon also verifies a callable's `Authorization` bearer before it forwards the call, for Node and Python codebases alike. A request that carries more than one `Authorization` header is refused with 401 before anything is forwarded.

## When the event queue is full

The runtime holds at most 4096 undelivered events (and 64 MiB of payloads). An event that does not fit is never lost silently, and what happens depends on its source:

- **Firestore, Storage, the Pub/Sub emulator and a control Pub/Sub publish:** the write or publish is refused, and nothing is delivered. A control publish answers `429 RESOURCE_EXHAUSTED`.
- **Authentication:** a user created or deleted is committed either way. Its events are held in a bounded queue and delivered, oldest first, when capacity returns; only a backlog beyond 4096 held events drops one, and that drop is counted and logged.

<details>
<summary>Details</summary>

- Firestore, Storage, the Pub/Sub emulator and the control Pub/Sub publish (`POST /v1/sessions/{session}/pubsub/topics/{topic}:publish`) reserve the whole fan-out first, every message to every subscribed function with the copies a `duplicate` fault asks for. When it does not fit, the write or publish is refused (a control publish answers `429 RESOURCE_EXHAUSTED` and issues no message id) and nothing is delivered.
- An Auth user created or deleted is committed whether or not the queue has room, as production never refuses a sign-up because functions are behind. An event the queue cannot take yet is held and delivered when capacity returns, oldest first and whole. `GET /v1/sessions/{session}/functions` shows the held count as `authEventsPending`, and `await-idle` waits for it. At most 4096 events are held: one beyond that is dropped, counted as `admission.auth_event_dropped` in the resource report and logged. A session reset discards held events with the rest of the queue.

</details>

## Exports that never run

An export Fireemu cannot serve (a function whose options fail to resolve, or an event type it does not recognise) is skipped, and each one is a `warning:` on standard error at start, followed by a summary line. A function that production would deploy and run never runs here, so a test that asserts "no side effect" passes for the wrong reason; read the warnings. `functions.unservedTriggers` still refuses the products Fireemu does not serve.

## Runner output

Function logs and runner standard error are forwarded to the local logs. If the runner exits before its startup handshake, diagnostics also include its exit status, captured standard error and a bounded tail of standard output. Application-written output is not automatically scrubbed of arbitrary secrets; avoid printing credentials or dumping the environment in function code.

## Source reload

Node codebases reload source changes automatically. Already-admitted invocations finish on their selected generation, subject to their invocation deadlines. A retired generation that does not finish is stopped one second after its latest outstanding invocation deadline, except in debugger mode. Edits before the watcher's first scan are detected, and reload snapshots are removed at shutdown. Changing the discovered trigger manifest requires restarting Fireemu; a rejected reload normally keeps the previous generation. A fixed `--inspect-functions <port>` is an exception: the previous runner must stop before the replacement can bind that port. Python codebases still require a restart.

On Windows, reload snapshots are created with a protected DACL before source or local secret files are copied. Fireemu checks the snapshot directory, temporary parent and ancestors for unsafe permissions or reparse points, and refuses the snapshot if it cannot verify them. This requires Windows PowerShell; see [Troubleshooting](../../guides/troubleshooting/).

## Process isolation (`functions.isolation`)

Production runs every function in its own instance: the function's identity (`FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE`, `K_SERVICE`) and the secrets it declares are in its environment from the start, it has its own module graph, and a second-generation instance serves up to `concurrency` calls of that one function at a time (the first generation serves one). `functions.isolation` chooses how closely a run follows that.

| `functions.isolation` | Processes | What it means |
|---|---|---|
| `"codebase"` (the default) | One runner process per codebase | Cheapest to start. The functions share one module graph: module-level state, caches and singletons are visible to every function. They share one process environment too: `FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE` and `K_SERVICE` name the call that started most recently, so a function that reads one after an `await` while another function was called sees the other function. A call that uses a local secret from `.secret.local` runs alone, so it also hides concurrency a deployed function would have. Secrets are hidden from every function that does not declare them, while user code loads and while a call runs. |
| `"function"` | One runner process per function of each codebase | The shape of production. Each process loads the codebase on its own, starts with its function's identity and with the local secrets that function declares already in its environment (so module-level code that reads them sees them), and serves only that function, at the concurrency the function is configured for. Nothing is rewritten, hidden or queued per call. One function's process crashing or restarting does not touch the others. |

```json
{ "schemaVersion": 1, "functions": { "isolation": "function" } }
```

With `"function"`, Fireemu first starts a discovery process to read the codebase's exports, then starts one process per served function and stops the discovery process. A codebase with more than 64 served functions is refused (a Node or Python process each); keep `"codebase"` for it. A function whose process exits is restarted on its next use, the same way a codebase process is, and a source reload replaces every process of the codebase together: if the reload changes which functions the codebase serves, it is rejected and the previous processes keep running. The log lines of every process are forwarded as for the codebase process, and the status of the control API lists one entry per process with its `function`.

`"function"` costs one process (and one copy of the loaded codebase) per function: more start-up time and memory than `"codebase"`, growing with the number of functions. It cannot be combined with `functions.runner` (a custom runner command is started once per codebase) or with a fixed `--inspect-functions <port>` (processes cannot share a port; `--inspect-functions` without a port gives each process its own). It applies to Python codebases too.

## Debugging

Run the Functions runner under the Node inspector with `--inspect-functions`:

```sh
npx fireemu up --inspect-functions 9229
```

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

## Production verification

Node.js codebases are verified against recordings from deployed functions for HTTP and callable functions, for event triggers and for scheduled functions. See the [compatibility tables](../../compatibility/#production-verification).

Python codebases have their own verification statement, for six event families; see [Production verification](../functions-python/#production-verification) on the Python page.
