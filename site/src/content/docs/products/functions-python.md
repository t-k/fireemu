---
title: Cloud Functions (Python)
description: Run Python Cloud Functions for Firebase codebases locally, and where they differ from production and from Node.js codebases.
---

Fireemu runs Python codebases next to Node.js ones. This page covers what is specific to Python. The [Cloud Functions](../functions/) page describes the Node.js runner; the sections there that also apply to Python codebases, such as [App Check in callables](../functions/#app-check-in-callables), say so.

## Set up

A codebase is Python when its `runtime` in `firebase.json` is `python310`, `python311`, `python312`, `python313` or `python314`, or when it declares no `runtime`, has no `package.json` and has a `requirements.txt` (the order the Firebase CLI uses). Fireemu runs it with the interpreter of the codebase's own virtual environment, always `<source>/venv/bin/python`, and never creates the environment or installs packages:

```sh
cd functions
python3.12 -m venv venv
venv/bin/pip install -r requirements.txt   # includes firebase-functions
npx fireemu up
```

Before anything starts, fireemu checks the environment and stops with the Firebase CLI's message when `venv` is missing or `firebase_functions` cannot be imported, and with a message naming both versions when the interpreter's Python differs from the declared `runtime`. The tested SDK is `firebase-functions` 0.6.0. Linux and macOS only.

## Supported triggers

Fireemu serves HTTP (`https_fn.on_request`), callable (`https_fn.on_call`), Firestore document triggers (`on_document_created`, `updated`, `deleted`, `written` and the `_with_auth_context` variants), Pub/Sub (`pubsub_fn.on_message_published`), Cloud Storage (`storage_fn.on_object_finalized`, `deleted`, `archived`, `metadata_updated`), Eventarc custom events (`eventarc_fn.on_custom_event_published`) and Realtime Database (`db_fn.on_value_created`, `updated`, `deleted`, `written`) triggers. It also serves scheduled functions (`scheduler_fn.on_schedule`), task queue functions (`tasks_fn.on_task_dispatched`) and Auth blocking functions (`identity_fn.before_user_created`, `before_user_signed_in`). A callable sees the user of the Auth emulator. A trigger for a product fireemu does not serve is reported when the codebase loads and never runs; discovery refuses such a codebase unless `functions.unservedTriggers` is `"report"`, as for the products listed under [Supported triggers](../functions/#supported-triggers) on the Cloud Functions page.

## Auth blocking functions and the audience check

With firebase-functions (Python) 0.6.0 and firebase-tools 15.28.2, production delivers a token whose `cloudfunctions.net` audience the Python SDK refuses: the function fails closed and sign-up returns 503 `Error code: 47`. By default fireemu runs the function, as the official emulator does, and prints a diagnostic line about this production failure. To reproduce it, set `productionExact` to `true`, or set `functions.authBlockingToken` to `"production"` under the strict profile. Node functions receive the same production-shaped token but do not verify it, so they behave as before. A later firebase-functions or firebase-tools release may change the audience rule; this setting follows the SDK installed in the codebase's own virtual environment, and only 0.6.0 has been recorded.

## Production verification

Python codebases are verified against production for six event families, each from two independent production recordings under the `strict` profile: Firestore, Pub/Sub, Cloud Storage, Eventarc custom events, Cloud Scheduler and Cloud Tasks. The comparison covers the values and request projections the Python SDK sees; see the [compatibility tables](../../compatibility/#production-verification). Python Auth blocking functions are not verified, and deployment of a Python codebase to production was not compared. The emulator profile's differences from the recorded `strict` behaviour are listed as known differences in those tables and in the list below.

## Differences from production and the Firebase CLI

Python codebases differ from production and from the Firebase CLI in these ways:

- By default one Python process serves the whole codebase, where production gives each function its own instance and the CLI its own process. `functions.isolation = "function"` starts one process per function instead (see [Process isolation](../functions/#process-isolation-functionsisolation)); the rest of this bullet and the secrets bullet describe the default. Module-level state is shared between functions, the `@init` callback runs once per process, on the first call of any function, and `FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE` and `K_SERVICE` name the function that started most recently when calls overlap.
- Time is real time. Python code is not moved onto the virtual clock, so `datetime.now()` ignores `daemon.clock` settings; a configuration that asks for a virtual date for the Functions runner is refused for a Python codebase.
- Python source changes reload automatically. A valid edit starts a replacement from a consistent source snapshot; an invalid edit keeps the last-known-good generation serving and later valid edits can recover it. Ordinary source symlinks to files or directories, including targets outside the source directory, are materialized under their link names in each snapshot; edits through the alias trigger reloads. Changes inside `venv` do not trigger reloads, so restart Fireemu after changing installed dependencies or the virtual environment. Python bytecode caches (`__pycache__`, `.pyc` and `.pyo`) are ignored.
- An `async def` handler is not run. The Python SDK never awaits a handler, so in production the body of an `async` event or scheduled function is silently skipped (and an `async` HTTP function answers 500). Fireemu reports such an invocation as failed with that reason, and an `async` HTTP function answers 500 with it; declare the handler with `def`.
- A scheduled function is called as Cloud Scheduler calls it, through the SDK's request wrapper: a handler that raises is logged by the SDK and fails the attempt, and the schedule time the handler sees is written in Los Angeles time in the strict profile and in UTC in the emulator profile (the same instant).
- Secrets from `.secret.local` are in the environment only while a function that declares them runs: a function with a secret runs alone, in arrival order, and every function without one runs with all local secrets hidden, beside other such functions. Functions without secrets are never held up by each other. The isolation lasts for the invocation and its response. Work a function leaves running afterwards, such as a thread it started or a child process, runs in the shared process and can see whatever the environment holds at that moment; the Node runner behaves the same. A function that holds a secret and calls another function of the same codebase synchronously (an HTTP request to its own URL, for example) waits for the gate it holds and never finishes, as in the Node runner; call such functions asynchronously or give the caller no secret.
- Python Storage and Eventarc handlers parse the event `time` with a fractional-second pattern, so production's SDK fails on a whole-second time. The strict profile delivers the time as production does; the emulator profile adds `.000` to a whole-second time, as the official emulator's events always carry milliseconds.
- `--inspect-functions` is ignored with a warning, as the Firebase CLI does.
- App Check for a Python callable is checked by the Python SDK itself, as in production. It verifies the `X-Firebase-AppCheck` token with the Admin SDK, and Fireemu points that check at the App Check emulator's keys, so only a token the emulator signed is accepted and an `enforce_app_check=True` callable answers 401 to every other call.
  - The runner fetches those keys itself, from a loopback address only, without following redirects or using a proxy.
  - Beyond the SDK's checks it requires an expiry and an issuer of exactly the form the emulator issues, and its project number must agree with the `projects/<number>` audience; the audience rule is the SDK's own (`projects/<project id>`).
  - This needs PyJWT 2.10.1 or later, which the Admin SDK's own constraint already implies; with an older one nothing is announced and the header is removed.
  - It works when the run has an App Check emulator, which the strict profile starts with Functions. Without one the header is removed before the function and no callable sees a token.
  - Differences from Node: the Python SDK checks the token against the keys alone, so unlike a Node callable (whose tokens the daemon also checks against the project's current epoch and app state) a token stays valid after you reset the project or disable the app until it expires. There is no start-up self-test of the SDK. The SDK checks the token's times against real time while the emulator signs them on its own clock, so a token minted after you moved the clock ahead of real time is refused as not yet valid. Limited-use token consumption (`verify_token(..., consume=True)`) is refused. A configuration that turns App Check on explicitly (`appCheck` in the configuration file) refuses to start with a Python codebase.

## Event bodies

CloudEvent handlers can read `flask.request`: it represents the delivering `POST /`, including binary-mode `ce-*` headers, content type, length and body. Firestore uses a protobuf body. Under `strict`, Pub/Sub uses sorted compact JSON with a newline, Storage uses its recorded indented JSON layout, Eventarc preserves the publisher's JSON body text, and trace context is a plain `traceparent` header rather than a CloudEvent attribute. Firestore has `dataschema` only under `strict` (recorded for created events; other event types are unobserved). For JSON event bodies, the emulator profile keeps the daemon's framed JSON value text, except that Pub/Sub adds the SDK's snake-case aliases and compacts the body. Realtime Database body layout is unrecorded; Cloud Run authorization and identity headers such as `Function-Execution-Id`, `Forwarded` and `X-Forwarded-For` are not reproduced.
