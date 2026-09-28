# Functions generation and Task Queue dispatch boundary

This is a local Node-runner contract, not native/SDK/production acceptance.

## Fixed metadata source

`firebase-functions@7.3.2` exposes v1 `tasks.taskQueue().onDispatch` as an HTTP
wrapper with `__endpoint.platform = "gcfv1"` and `taskQueueTrigger`. It also
exposes a legacy `__trigger.taskQueueTrigger`. `run(data, context)` is the
user-handler entry for tests; HTTP dispatch must call the exported wrapper, not
`run`, so the SDK remains responsible for request decoding and TaskContext.

The runner now recognizes both v1 metadata representations and retains the v2
Task Queue path. A queue declaration takes precedence over a generic
`httpsTrigger` when both are present. It preserves region, timeout, retryConfig
and rateLimits, including zero/null option values. Missing or null configuration
records use `{}`; a non-null non-object record is named in `ignored` rather than
silently becoming a default queue. No queue scheduling, IAM policy, retry or
concurrency enforcement is implemented by this change; those remain native
integration obligations.

## Identity and calling convention

`FUNCTION_SIGNATURE_TYPE` is `http` for HTTP/callable, Tasks and Blocking Auth in
both generations. Schedules use `event` for generation 1 and `http` for generation
2. Other served events use `event` for generation 1 and `cloudevent` for generation
2. This fixes the previous `cloudevent` value in HTTP Tasks and Blocking Auth.

The callback argument convention uses the generation recorded in the announced
manifest. Invocation must not re-read a function's mutable `__endpoint` or
`__trigger`: changing/removing those fields after discovery, or making them
throw, does not switch a published v1 callback to a v2 event object or vice versa.
Nonempty endpoint metadata with an unknown/missing platform is `ignored`; an
empty endpoint can still fall back to legacy `__trigger`. These malformed-input
and metadata-freezing decisions are local consistency policies, not claims about
how a production deployment reports them.

This binds only the generation/calling convention and the existing function
selection. It does not freeze arbitrary callback code or every nested metadata
object, isolate code running in one Node process, authenticate a deployment, or
make process-wide environment variables invocation-local. The existing shared
process concurrency semantics and secret-environment queue remain unchanged.

## Executable checks and limits

`tools/runner-node/generation-runner.test.mjs` runs the actual Node entry point,
framed IPC and loopback HTTP. Fixtures reproduce the pinned SDK metadata and
include v1/v2 Tasks, legacy fallback, HTTP/Blocking environment identity, retained
retry/rate options, post-discovery metadata changes, v1/v2 event argument shapes,
and proxy/project/region/IPC rejection. Express, body parsing and the Task Queue
HTTP wrapper in this test are explicit test doubles. This is not an installed
Firebase SDK, native task queue, actual retry scheduler, or deploy test.

Required follow-up: run the existing locked SDK/native discovery and runtime
lanes, including v1 TaskQueueFunction and v2 onTaskDispatched, and the Auth Blocking
integration. Earlier saved evidence is immutable and is not refreshed by this
Node-only check.

## Primary sources

- https://github.com/firebase/firebase-functions/blob/v7.3.2/src/v1/providers/tasks.ts
- https://github.com/firebase/firebase-tools/blob/v15.28.2/src/emulator/functionsEmulatorShared.ts
