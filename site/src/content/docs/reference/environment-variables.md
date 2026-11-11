---
title: Environment variables
description: The environment variables Fireemu sets for your command and the ones it reads.
---

This list is taken from the source of the `fireemu` binary and the npm package. Anything not listed here is an implementation detail and may change.

## Set by `fireemu exec`

`exec` gives its command the variables of the emulators that are running, and nothing else of its own. Variables for emulators that are not selected are left as your environment had them, so a missing emulator never sends an SDK to production by accident; `exec` prints a warning for each one, and `--deny-inherited-emulator-env` refuses the run instead (see [Inherited emulator variables](../cli/#inherited-emulator-variables)). The names and formats follow what `firebase emulators:exec` writes.

| Variable | Value | When |
|---|---|---|
| `FIRESTORE_EMULATOR_HOST`, `FIREBASE_FIRESTORE_EMULATOR_ADDRESS` | Firestore `host:port` | Firestore runs |
| `FIREBASE_AUTH_EMULATOR_HOST` | Authentication `host:port` | Authentication runs |
| `FIREBASE_STORAGE_EMULATOR_HOST` | Storage `host:port` | Storage runs |
| `STORAGE_EMULATOR_HOST` | Storage URL (`http://host:port`) for the Cloud Storage client libraries. With Storage App Check `enforced` and `appCheck.storageServerRequests` set to `"capability"` it also carries a per-run Admin capability (see [App Check](../../products/app-check/)) | Storage runs |
| `FIREBASE_DATABASE_EMULATOR_HOST` | Realtime Database `host:port` | The Realtime Database runs |
| `PUBSUB_EMULATOR_HOST` | Pub/Sub `host:port` | Pub/Sub runs |
| `CLOUD_EVENTARC_EMULATOR_HOST` | Eventarc URL (`http://host:port`) | Functions run |
| `CLOUD_TASKS_EMULATOR_HOST` | Cloud Tasks `host:port` | Functions run |
| `FIREEMU_FUNCTIONS_HOST` | Functions `host:port` | Functions run |
| `FIREEMU_APP_CHECK_EMULATOR_HOST`, `FIREEMU_APP_CHECK_JWKS_URL` | App Check exchange host and JWKS URL | App Check is available (see [App Check](../../products/app-check/)) |
| `FIREBASE_EMULATOR_HUB` | Emulator Hub `host:port` | The Hub runs |
| `FIREBASE_LOGGING_EMULATOR_HOST` | Logging emulator `host:port` | The Logging emulator runs |
| `GCLOUD_PROJECT`, `GOOGLE_CLOUD_PROJECT` | The project ID | Always |
| `FIREBASE_CONFIG` | Set from the project ID | Unless your environment already has it |
| `FIREEMU_CONTROL_URL` | Base URL of the control API, ending in `/v1/` | Always |
| `FIREEMU_CONTROL_TOKEN` | Bearer token for the control API; used by `fireemu/testing` and by the scripts in [Cloud Firestore](../../products/firestore/#fail-a-ci-job-on-a-missing-index) | Always |

`fireemu up` does not set variables in your shell. Its startup output prints each `host:port` (for example `FIRESTORE_EMULATOR_HOST=127.0.0.1:8080`), and the Emulator UI shows them on the Overview page under "Environment for SDKs".

## Set for Functions code

A Functions codebase runs with the same emulator host variables for the services that are running, plus `FUNCTIONS_EMULATOR=true`, the project ID variables and `FIREBASE_CONFIG`. Only a short list of variables is inherited from the daemon. Credentials are withheld on purpose: `GOOGLE_APPLICATION_CREDENTIALS`, `FIREBASE_TOKEN` and `CLOUDSDK_*` do not reach function code. The `FIREEMU_RUNNER*` variables are internal.

## Read by Fireemu

| Variable | Effect |
|---|---|
| `FIREEMU_BINARY_PATH` | The `fireemu` launcher runs this binary instead of the platform package's. For a platform without a published binary, or a binary you built. |
| `FIREEMU_NODE` | Absolute path of the Node.js executable that runs Functions codebases. Refused when it is not an absolute path to an executable file. Without it, Fireemu looks for `node` in the `PATH` directories (and Volta's, see `VOLTA_HOME`). |
| `FIREEMU_RUNNER_NODE`, `FIREEMU_RUNNER_PYTHON` | Path of a Functions runner script (`index.mjs`, `runner.py`) to use instead of the bundled one. An error when the file does not exist. |
| `FIREEMU_WORKER_THREADS` | Number of async worker threads, 1 to 64. Default: the number of available cores, at most 4. |
| `FIREEMU_MAX_BLOCKING_THREADS` | Upper bound of blocking threads, 1 to 512. Default: 64. |
| `FIREEMU_CONTROL_TOKEN` | `fireemu doctor --connect` sends it as the bearer token to the control API. Inside `fireemu exec` it is already set. |
| `FIREBASE_CONFIG` | When `exec` finds it set, it keeps your value instead of writing one from the project ID. |
| `PATH`, `VOLTA_HOME` | Where Node.js is looked for when `FIREEMU_NODE` is not set. |
| `HOME`, `XDG_CACHE_HOME`, `LOCALAPPDATA` | Where the cache of the Authentication session signing key is kept (an owner-only directory); without a usable cache the key is generated in memory at each start. |
| `SUDO_UID` | When Fireemu runs as root, the user named here is also a trusted owner of discovered configuration files. See [file ownership checks](../../guides/configuration/#file-ownership-checks). |
| `ComSpec` | On Windows, the shell that runs the script form of `fireemu exec "script"`. Default: `cmd.exe`. |
| `FIREEMU_TRACE_WEBCHANNEL`, `FIREEMU_TRACE_STORAGE` | Any value prints a request trace (`[webchannel] ...`, `[storage] ...`) on standard error, for diagnosing a client problem. Not for regular runs. |
