# Node runner IPC boundary and failure delivery

This local runner work supports Functions event delivery and the Auth/Functions
integration. It is not an independent native/SDK compatibility acceptance.

## Input framing

The daemon emits `<decimal byte length>\n<UTF-8 JSON payload>` through a private
stdin pipe. The Node reader now requires the canonical positive decimal spelling
that the Rust `encode_frame` produces: no sign, padding, whitespace, suffix or CR.
The maximum payload is 16 MiB, matching `MAX_FRAME_BYTES` in
`crates/fireemu-adapter-functions/src/protocol.rs`. The length is checked before
body allocation; a partially received body is copied into one capped buffer,
without repeatedly concatenating all previously received bytes. The per-frame cap bounds one
pending frame. Separate limits below cover active IPC payloads, not total process memory.

Malformed UTF-8, malformed JSON, non-object messages, invalid mandatory invocation
fields, and unknown message types retire the runner with exit code 2. A partial
header or body at EOF is not a clean shutdown. The parser does not resynchronize
and execute frames following a bad one. Previously completed messages may already
have side effects; channel failure does not roll those back. Clean EOF and an
explicit `shutdown` abort active callbacks, but allow already-admitted protocol
output a bounded one-second flush before exit. This is not graceful callback
completion; see `node-runner-output-boundary.md`.

The supported messages remain `invoke` and `shutdown`. Other invocation metadata
is retained for forward compatibility. JSON data uses `JSON.parse`; this is not a
new universal JSON schema, duplicate-key policy, or validation of CloudEvent data.
Invalid-byte replacement is prohibited using fatal UTF-8 decoding. The Rust reader
and sender are unchanged and require native review/testing separately.

## Partial input residence time

A header and its body share a 30-second local receive deadline, starting when the
reader observes the first nonempty byte. It is **not** renewed when the header is
finished, another body fragment arrives, or an empty chunk is delivered. The
stream schedules a timer only while a frame is partial. A complete frame clears
that timer; a later frame has a new interval. An idle pipe, or an asynchronous
callback taking longer than 30 seconds, is not timed out by this mechanism.

The decoder also checks the clock on data arrival and after JSON decoding, before
dispatch. This rejects a late final fragment even if the timer's callback has not
yet run. Trailing frames in one coalesced chunk share that chunk's observed
arrival time, so a synchronous callback cannot renew time for bytes already
received behind it. Invalid or backwards clock readings are permanent failures.

On expiry the runner retires with exit 2 and a fixed diagnostic. No following
frame executes, and accepted callbacks may already have side effects. A receiver
timer does not cancel or roll back those side effects. This is a local safety
policy, not a Firebase function deadline or production quota. Timer callbacks
cannot interrupt synchronous user code, a stopped event loop or a kernel stall;
this is not an external/OS hard watchdog. The per-frame limit is fixed at the
runner entry point (no message/environment override); lower test options are
available only to the directly constructed parser.

Primary references for the timing API and its limits:
* Node timers: https://nodejs.org/api/timers.html#timeout-callback-delay-args
* Versioned performance clock: https://nodejs.org/download/release/v22.16.0/docs/api/perf_hooks.html#performancenow

## Dispatch identity

`function` must select a served manifest entry. An optional `entryPoint` must equal
that entry's recorded entry point, and `trigger` must match its supported IPC
trigger. The callback and its per-function environment are selected from the same
manifest entry. A well-shaped but mismatched request produces one failed result
without entering the callback. HTTP/task/blocking invocations stay on their
existing authenticated HTTP route; stdin cannot switch the trigger to bypass it.

A duplicate **in-flight** invocation ID retires the channel, rather than sending
two results to one daemon waiter. Different IDs may run concurrently, and a
completed ID is not permanently reserved. The existing secret/debugger queue is
unchanged. These checks are defense against inconsistent local requests, not
isolation between arbitrary user code sharing one Node process.

## Active IPC input budget

The receiver admits at most **4,096** unfinished IPC invocations and **64 MiB**
of their actual encoded JSON payload bytes. Header bytes are excluded, while
JSON whitespace, metadata and UTF-8 byte widths are included. The decoder passes
the original length; a sender's `payloadBytes` field or a reserialization does
not control accounting. A separate in-progress decoder buffer may hold one more
frame (up to 16 MiB), and the parsed object exists before admission.

A slot covers execution **and** waiting in the existing secret/debugger
environment queue. Reserve happens before callback entry. Completion or rejection
releases its lease once; completed IDs may be reused, and an old lease cannot
release a new invocation with the same ID. The callback's output is bounded by
the separate output queue after it finishes. A count/byte overflow retires the
runner with exit 2 rather than launching the excess callback, dropping results,
or claiming the older in-flight operations did not run. Failure is terminal:
releasing old slots cannot reopen a failed admission budget.

These are receiver-local defensive caps, not a new Firestore quota, semantic
concurrency setting or proof of native admission equivalence. Normal parallel
invocations are preserved below the caps. They do not cover HTTP callbacks,
post-return user references, V8 object expansion, serialization temporaries,
raw stderr, escaped descendants or the whole process RSS. Native integration and
load tests remain required; the Rust-side event count/byte accounting is not
changed by this receiver guard.

## Callback errors

`invocationFailure` snapshots a string message and stack at most once each. A
throwing getter, revoked Proxy, or non-error value cannot cause error formatting
to throw again. Arbitrary `toString`/`toJSON` hooks are not called. Failure result
messages are bounded to 4 KiB; diagnostics use the existing 256 KiB log bound.
Unpaired UTF-16 surrogates are normalized through the existing log helper so they
do not generate an invalid Rust-readable protocol string.

Diagnostic failures cannot suppress a failed IPC result or the generic HTTP 500
reply. This does not make a blocked stdout sink reliable, guarantee output across
process death, cancel arbitrary user code, or protect against global monkey
patching in the shared process.

## Distribution and evidence

The explicit platform-package allow-list includes both new runtime modules.
The existing manual Functions SDK workflow runs every runner test file rather
than a stale subset. Changing that workflow file does not execute remote CI.

Local tests run the actual runner through real child-process pipes with plain
Functions-shaped fixtures (without Firebase SDK). HTTP integration uses the
existing small Express/HttpsError test doubles. The package test copies the real
runner modules through `buildPlatformPackage` and boots that copy; the placeholder
native file is never executed. This is not a native build or an npm installation.

Normal cases include fragmented multibyte input, coalesced frames, a full 16 MiB
message, concurrent IDs, completed-ID reuse, v1 Auth delivery, omitted optional
entry point, per-function secret selection, and continued service after callback
failure. Counterexamples include truncated EOF, invalid length spellings,
oversized headers, malformed UTF-8/JSON, invalid envelopes, mismatched dispatch,
active-ID reuse, throwing error accessors, partial input residence deadlines,
active callback/environment-queue count and byte exhaustion, and output-module omission.

## Non-production work still required

Rust/native adapter integration, real Firebase SDK/Express, the configured Node
24 CI environment, current binaries and source-bound shadows, previous native
changes, and independent review remain unexecuted. Export graph handling is described separately in
`node-runner-export-discovery.md`. Protocol stdout backpressure and its limits are
covered separately in `node-runner-output-boundary.md`; raw user stderr and total
process memory are not bounded by that writer. Existing saved compatibility
receipts and approval bindings are not rewritten. No production is authorized.
