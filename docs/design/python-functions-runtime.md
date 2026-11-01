# Design memo: Python Cloud Functions (2nd gen) in fireemu

Status: proposal (stage 1 of 2). Nothing here is implemented yet; stage 2 implements it after review.

## Problem

Production runs Python Cloud Functions for Firebase (2nd gen) as a GA runtime. fireemu runs Node
only: `crates/fireemu/src/config.rs` (`check_codebase_runtime`) refuses a codebase whose `runtime` is
`python3xx` by name, and `crates/fireemu/src/capabilities.json` records "Python (functions-framework)
and Dart loader paths: refused by name, never handed to node". A project with a Python codebase
therefore cannot use fireemu for that codebase at all.

Scope: 2nd gen only (the only generation the Python SDK offers), Linux and macOS. Windows and Dart
stay out.

## What the official toolchain does (firebase-tools 15.28.2)

Read from the published npm package `firebase-tools@15.28.2` (`lib/`, compiled JS; line numbers are
of that version):

- **Detection.** `lib/deploy/functions/runtimes/python/index.js:16-30` (`tryCreateDelegate`): a
  codebase is Python when `requirements.txt` exists in its source directory. The runtime is the
  declared `runtime` or the latest supported Python (`supported.latest("python")`); runtimes
  `python310` to `python314` are known (`lib/deploy/functions/runtimes/supported/types.js:68-92`).
- **Interpreter.** `index.js:31-51` (`getPythonBinary`) maps the runtime to `python3.10` ...
  `python3.14` (`python.exe` on Windows).
- **Virtual environment.** `lib/functions/python.js:10` (`DEFAULT_VENV_DIR = "venv"`) and `:19-30`
  (`runWithVirtualEnv`): every Python command runs as `. "<source>/venv/bin/activate" && <command>`
  through a shell in the source directory, with `process.env` plus the extra variables.
- **SDK location.** `index.js:67-102` (`modulesDir`): runs `python3.x -c "import firebase_functions;
  ... print(os.path.dirname(firebase_functions.__file__))"` in the venv. An empty answer is an
  error: "Missing virtual environment at venv directory. Did you forget to run 'python3.x -m venv
  venv'?" (`:93-94`) or "Failed to find location of Firebase Functions SDK. Did you forget to run
  '. venv/bin/activate && python3.x -m pip install -r requirements.txt'?" (`:97-98`).
- **Manifest discovery.** `index.js:149-164` (`discoverBuild`): first `functions.yaml` in the source
  directory (`lib/deploy/functions/runtimes/discovery/index.js:33-50`, `detectFromYaml`); otherwise
  it starts the SDK's admin server, `python3.x <sdk>/private/serving.py` with `ADMIN_PORT` set
  (`index.js:115-123`, port from `portfinder` starting at 8081, `:152-154`), polls
  `GET http://127.0.0.1:<port>/__/functions.yaml` (`discovery/index.js:51-87`, 10 s default timeout,
  connection errors retried) and stops it with `GET /__/quitquitquit` (`index.js:132`). The SDK side
  (`firebase-functions` 0.6.0, `firebase_functions/private/serving.py:36-53,120-154`) imports `main.py`
  from the working directory, collects every module function carrying `__firebase_endpoint__`, and
  serves the YAML manifest. The manifest is the same `functions.yaml` endpoint schema the Node SDK
  produces.
- **Execution.** `lib/emulator/functionsEmulator.js:1134-1155` (`startPython`): one
  `functions-framework` process per worker, run in the venv with `PORT=<random 8081-9081>`,
  `HOST=127.0.0.1`, `PYTHONUNBUFFERED=1`, `DEBUG=False`, plus the runtime environment. The function
  to serve is chosen by environment, not by the request: `getSystemEnvs` sets
  `FUNCTION_TARGET=<entryPoint>`, `FUNCTION_SIGNATURE_TYPE` and `K_SERVICE` per trigger
  (`functionsEmulator.js:977-990`), and the emulator sets `FUNCTIONS_EMULATOR=true`, `TZ=UTC`,
  `FIREBASE_DEBUG_MODE=true` and `FIREBASE_DEBUG_FEATURES` (`:991-999`). The worker then receives the
  event over HTTP on that port (`TCPConn`, `:1153`).

That last point is the property fireemu must not copy: the target is fixed by the process environment
and the event arrives on a separate HTTP channel, so a worker started for one trigger can be handed
another trigger's event (firebase-tools issue #11263).

## What fireemu's Node path does today

`tools/runner-node/index.mjs` is one long-lived process per codebase, speaking length-prefixed JSON
frames on stdin/stdout. It loads the codebase, discovers the manifest itself, and announces it in a
`hello` frame (`:1832-1834`), together with the port of the local HTTP server that hosts `onRequest`
and `onCall` functions. An event invocation is one frame that carries the function name, the trigger
and the event together; `invoke()` (`:1534-1545`) looks the function up in the manifest and refuses
the frame when the entry point or the trigger type does not match it. Results are frames keyed by
`invocationId`. Clock control (`clock:set`, `clock:runDue`), log frames and the admin App Check
channel share the same pipe. The daemon side is `crates/fireemu-adapter-functions` (`runner.rs`,
`protocol.rs`, `runtime.rs`).

## Proposal

### 1. Discovery and manifest

- A codebase is Python when its `runtime` starts with `python3`, or, with no `runtime`, when
  `requirements.txt` exists and `package.json` does not (firebase-tools only looks at
  `requirements.txt`; requiring the absence of `package.json` keeps today's Node codebases with a
  stray `requirements.txt` on the Node path; open question 1).
- The interpreter is `<source>/venv/bin/python` (not `python3.x` on `PATH` plus `activate`): the
  venv's own interpreter is what `activate` would select, it needs no shell, and its version is
  checked against the declared runtime (`python3.12` for `python312`); a mismatch is a load error
  naming both.
- `functions.yaml` in the source directory wins, as in firebase-tools. Otherwise the Python runner
  (below) imports `main.py` and builds the manifest through the SDK's own
  `firebase_functions.private.serving.get_functions()` / `functions_as_yaml()`, so the manifest is
  exactly what the SDK would serve on `/__/functions.yaml`, without a second admin server process and
  port.
- The manifest feeds the existing `manifest_json.rs` parsing unchanged: the YAML is the same endpoint
  schema, converted to the JSON the Node runner sends in `hello`.

### 2. Runner process model and wire protocol

- **One runner per codebase, like Node** (`tools/runner-python/runner.py`, run with the venv
  interpreter without `-I`, so `main.py`'s own imports resolve, in the source directory).
  Not one process per trigger as firebase-tools does: fireemu's runtime already bounds concurrency,
  restarts a dead runner per codebase and accounts invocations per runner, and one process keeps the
  memory of a large project bounded.
- **The same frame protocol as Node**: length-prefixed JSON on stdin/stdout, `hello` with the
  manifest and the HTTP port, `invoke` frames carrying `function`, `entryPoint`, `trigger`, `event`
  and `invocationId` together, `result` frames, `log` frames, `clock:set` / `clock:runDue`. The
  runner checks every `invoke` frame against its manifest exactly as `invoke()` does in Node (unknown
  function, entry point mismatch, trigger mismatch: refused). The target and the event never travel
  separately, so #11263 cannot occur.
- **Event delivery inside the runner**: the SDK's decorated functions take a CloudEvent
  (`cloudevents.http.CloudEvent`, as `functions-framework` would build). The runner builds that object
  from the frame's structured CloudEvent and calls the decorated function directly; it does not run
  `functions-framework` and does not open a port for events.
- The daemon side reuses `runner.rs` with a per-language launch spec (program, arguments,
  environment); `protocol.rs`, `runtime.rs` and the invocation accounting do not change.

### 3. HTTP and callable functions

- The runner hosts `https_fn.on_request` and `https_fn.on_call` functions on a loopback HTTP server
  (the SDK's request objects are Flask/Werkzeug, so a Werkzeug server on `127.0.0.1:0`), announced in
  `hello` like Node's express port, and the daemon proxies to it exactly as it proxies to Node.
- Callable semantics (auth context from the ID token, App Check header handling, error mapping) are
  the SDK's own, since the SDK's `on_call` wrapper runs; the daemon keeps doing what it does for Node
  in front of it (admission, App Check enforcement decisions, the `callable_trust` checks).

### 4. Triggers delivered in stage 2

From the Python SDK modules (`firebase_functions/*_fn.py`, 0.6.0):

| SDK module | trigger | stage 2 |
| --- | --- | --- |
| `firestore_fn` (`on_document_*`, `*_with_auth_context`) | Firestore | yes |
| `storage_fn` (`on_object_*`) | Storage | yes |
| `pubsub_fn.on_message_published` | Pub/Sub | yes |
| `scheduler_fn.on_schedule` | schedule (through the virtual clock, as Node) | yes |
| `eventarc_fn.on_custom_event_published` | Eventarc custom events | yes |
| `https_fn.on_request` / `on_call` | HTTP / callable | yes |
| `db_fn.on_value_*` | Realtime Database | yes, if the RTDB bridge payload needs no Node-only shaping (open question 3) |
| `identity_fn.before_user_created` / `before_user_signed_in` | Auth blocking | yes: the SDK supports them; same daemon contract as Node |
| `tasks_fn.on_task_dispatched` | Cloud Tasks | yes (an HTTP function underneath) |
| `remote_config_fn`, `test_lab_fn`, `alerts` | not emulated for Node either | no: listed as ignored in `hello`, as Node does |

### 5. Environment variables

The runner process gets what the Node runner gets today (project, `GCLOUD_PROJECT`,
`FIREBASE_CONFIG`, emulator hosts, `FUNCTIONS_EMULATOR=true`, `TZ=UTC`, params and secrets resolved
by the daemon), plus `PYTHONUNBUFFERED=1`. Per-invocation values that firebase-tools passes through
the process environment (`FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE`, `K_SERVICE`) are set for the
duration of one invocation by the runner, from the frame, for user code that reads them, and are
never used to choose the function.

### 6. venv and dependency errors

Load errors are reported before any listener binds, as other configuration errors are, with
firebase-tools' wording where it exists:

- no `venv/` directory: "Missing virtual environment at venv directory. Did you forget to run
  'python3.12 -m venv venv'?";
- `firebase_functions` not importable: "Failed to find location of Firebase Functions SDK. Did you
  forget to run '. venv/bin/activate && python3.12 -m pip install -r requirements.txt'?";
- venv interpreter version differs from the declared runtime: names both versions;
- `main.py` missing or raising at import: the SDK's own message ("could not find the main.py file")
  or the traceback's last line, with the codebase name.

fireemu never creates the venv or installs packages.

### 7. Logging

stdout is the protocol channel, so the runner redirects `sys.stdout` and `sys.stderr` of user code to
log frames, exactly as the Node runner does for `console.*`. `firebase_functions.logger` writes
structured JSON lines; the runner forwards them as structured log entries (severity, message, extra
fields) to the Logging emulator through the existing log-frame path.

### 8. What is shared with the Node runner

Shared: the frame protocol and its framing code on the daemon side, the manifest model, trigger
routing, retries and dead letters, the virtual clock and catch-up, admission and concurrency
budgets, App Check and callable trust, the HTTP proxy, the process-group lifecycle and restart.
Per language: the runner program and the language-side event shaping (CloudEvent construction for
the Python SDK).

## Test plan and acceptance criteria

- **Real SDK in CI on Linux**: a fixture codebase `tools/sdk-smoke/functions-python/` with
  `requirements.txt` pinning `firebase-functions` (0.6.0 at the time of writing),
  `functions-framework` and `firebase-admin` with hashes; CI creates its venv on Python 3.12 and runs
  smokes under `fireemu exec` in the default and strict profiles: one function per trigger in the
  table above, driven through `awaitIdle` and the virtual clock, the way
  `tools/sdk-smoke/functions.mjs` drives the Node fixture.
- **Protocol tests** (Rust, against a fake Python runner as for Node): mismatched `function`,
  `entryPoint` or `trigger` in an `invoke` frame is refused; a runner exit resolves outstanding
  invocations as runner-gone; output on stdout from user code cannot corrupt the frame stream.
- **Error tests**: each load error above, with its message, before any port binds.
- Acceptance: a Python codebase loads under `runtime: python312` and under no runtime with a
  `requirements.txt`; every stage-2 trigger fires once per event with the production payload shape
  (compared with the Node SDK's payloads, which are already production-checked); retries and dead
  letters behave as for Node; the `check_codebase_runtime` refusal remains for Dart and unknown
  runtimes; `capabilities.json` and the compatibility contract record the new loader path.

## Open questions

1. Detection without a `runtime`: follow firebase-tools exactly (`requirements.txt` alone means
   Python) or keep a codebase with both `package.json` and `requirements.txt` on Node?
2. Interpreter selection: require `venv/bin/python` (proposed) or also honour a non-`venv`
   directory, which firebase-tools does not?
3. Realtime Database events: does the Node runner apply shaping to RTDB events that the Python SDK
   would need differently?
4. Python versions in CI: 3.12 only, or a matrix up to 3.14 as firebase-tools supports?
5. Debugging: firebase-tools ignores `--inspect-functions` for Python (`functionsEmulator.js:1136-1138`);
   fireemu should do the same and say so, unless a `debugpy` hook is wanted.
