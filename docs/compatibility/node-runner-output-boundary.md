# Node runner protocol output: bounded queue and failure semantics

This is a local Functions runner resource policy. It is not a Firebase quota,
whole-process memory limit, production parity result, or independent native/SDK
acceptance. The Rust adapter's protocol bytes and limits are unchanged.

## Ordered, finite output

`output.mjs` captures the original stdout writer before the runner redirects user
stdout to stderr. Each hello/log/result is serialized once into a private complete
UTF-8 frame. Its byte-length header and body are submitted together; subsequent
mutation of the source object cannot alter an admitted frame. Serialization errors
and output payloads over the existing 16 MiB protocol limit fail **before** the
header is published. Reentrant protocol serialization is terminal as well.

One stream write is outstanding at a time. The writer waits for its callback; if
`write()` returned false, it also waits for `drain`, in either event order. False
means that the frame was already accepted by the stream, not permission to replay
it. Queued frames remain FIFO, and their memory stays in the explicitly bounded
writer instead of being passed to an unbounded Node Writable queue.

| Local bound | Value |
|---|---:|
| Payload in one output frame | 16 MiB (existing Rust protocol cap) |
| Encoded pending bytes, including headers and outstanding write | 32 MiB |
| Pending frames, including outstanding write | 1,024 |
| Residence time of each pending frame / a required drain | 30 seconds |
| Already-admitted output flush on clean EOF / explicit shutdown | 1 second |

The oldest frame's deadline is not renewed by later messages, partial progress,
or repeated drain events. Timer handlers and write callbacks both check elapsed
monotonic time, so a late callback does not win against a delayed timer. Limits
apply to synchronous callback log bursts too, even if the reader would otherwise
be fast: callbacks cannot enqueue arbitrarily many frames in one event-loop turn.

Byte/count overflow, output errors/closure, invalid serialization, and expired
output waits permanently fail the channel. The runner retires with exit code 2
and a fixed diagnostic, not user payload fragments. No log/result is silently
removed to make room for a successful result. Earlier frames and callback side
effects may already have reached their destinations: retirement is **not** a
rollback or proof of non-application. The existing native reader resolves missing
results as `RunnerGone`; its actual integration still requires native tests.

A local write callback confirms handling by Node/OS, not processing by the daemon
or database. `FrameWriter.send()` returning true means queued, not delivered.

## Shutdown

Clean EOF and an explicit shutdown stop admitting new output. Already-admitted
frames get up to one second to flush, also bounded by their original deadlines.
This fits inside the native adapter's existing two-second polite wait, without
changing its implementation. If the flush cannot be confirmed, exit is 2, not 0.
No frame after shutdown is dispatched by the input decoder. New HTTP callbacks
and callbacks still waiting in the environment/secret queue are refused during
the output drain.

Shutdown does **not** wait for all active callbacks or safely cancel their side
effects; the runner already aborted active callbacks on these inputs. Active code
may continue briefly during the bounded output drain, and its later logs/results
are not admitted. Protocol errors, capacity failures, or external termination can
still leave an incomplete last frame. Such failure is never advertised as a
successful output flush.

## Scope and limitations

This section bounds protocol output. Direct stderr/redirected stdout writes now
have the separate guard below. Neither guard bounds serialization's temporary
allocations, arbitrary getter/toJSON execution, global monkey-patching, or escaped
descendants. Input frames and IPC invocations have independent admission limits. Arbitrary user code shares the Node process.
Timers cannot interrupt a blocked event loop, synchronous OS writes, kernel or
filesystem stalls. The intended daemon connection is an asynchronous POSIX pipe;
Windows pipe behavior, actual native integration and the configured Node 24 lane
remain separate acceptance work. Node 22.16 tests are not those results.

References (official Node 22.16 API):
- https://nodejs.org/download/release/v22.16.0/docs/api/stream.html#writablewritechunk-encoding-callback
- https://nodejs.org/api/process.html#a-note-on-process-io

## Local evidence and reproduction

`output.test.mjs` uses actual Writable streams and instrumented sinks for FIFO,
callback/drain ordering, caps, one-time serialization, deadlines, errors and EOF.
`output-runner.test.mjs` runs the real index.mjs in a child process with plain
Functions-shaped callbacks: paused/resumed reads, byte/count floods, EPIPE,
oversized hello, buffered shutdown, concurrent callbacks and a real 30-second
blocked-output deadline. The copied platform-package runner is tested outside the
checkout too. Its native file is a never-executed fixture, not a built artifact.

```
node --test --test-concurrency=1 tools/runner-node/*.test.mjs
node --test --test-concurrency=1 npm/scripts/*.test.mjs
```

Other existing HTTP/Listen tests use SDK/Express substitutes. No SDK download,
remote CI, production operation, old evidence rewrite, or new permission occurs.
New source/native/SDK shadows, full workspace checks and independent review are
still required; selected tests do not close the 14 compatibility parents.


## Direct diagnostic writes (v33)

`diagnostic-output.mjs` is installed on `process.stderr.write` before importing
user code. Redirected `process.stdout.write` uses the same guard. These raw bytes
never enter the framed stdout protocol. The original stderr stream object, fd and cork/uncork behavior are retained.
A native false return remains false; an otherwise true native return can also
become false while completion callbacks still occupy the local budget. False
means accepted with backpressure, **not** permission to replay that chunk.

| Local bound | Value |
|---|---:|
| All outstanding raw diagnostic bytes | 8 MiB |
| Outstanding write calls, including empty chunks | 1,024 |
| Each write's residence time until its native callback | 30 seconds |
| EOF/shutdown flush, concurrent with protocol flush | 1 second |

Admission is enforced before calling the native writer, including synchronous
bursts and codebase initialization. Exact-size chunks pass. Bytes and callback
slots are released on write completion, so these are not lifetime quotas. The
oldest unfinished write keeps its original deadline despite later writes, drain,
partial progress or repeated finish calls. A late write callback also rechecks
that deadline. User callbacks remain asynchronous and run at most once.

Native synchronous writes may leave deferred callbacks even with no native bytes
buffered. The guard now provides additional backpressure at the smaller of the
byte cap and the native `writableHighWaterMark` (64 KiB fallback for an adapter
without that property), or when all callback slots are used. It keeps the hard
8 MiB/1,024 limits unchanged for producers that ignore false. The native `drain`
event is coalesced with logical pressure: a producer is notified asynchronously
only after native backpressure AND the tracked callbacks clear. This can delay
`drain` relative to raw Node ordering, but never treats a native drain alone as
write completion or resends a false-returning write. New writes from a completion
callback postpone the notification; failure/finish cancels further drain signals.
A cooperative producer using false/drain can continue when native writes happen
to complete synchronously rather than accumulating stale callback reservations.

String encodings and standard `setDefaultEncoding` are supported, as are Buffer,
TypedArray and DataView byte slices. Views are copied before admission to the
native queue, preventing later caller mutation from changing the pending bytes.
Intrinsic view getters avoid trusting shadowed byteLength/buffer properties.
Malformed hex/base64 encodings may have a conservative pre-allocation estimate;
only actual encoded bytes are charged after that check. Invalid argument types
remain synchronous TypeErrors rather than silently converted strings.

Overflow, deadline, EPIPE, close or write failure retire the runner with exit 2.
The raw-channel fatal handler deliberately does **not** write another diagnostic
to that failed channel. A different protocol-output failure may emit one bounded
terminal line (at most 256 bytes) using the captured native stderr writer, only
when stderr is healthy and has no pending writes. This preserves the failure
reason after ordinary admission closes; it is best-effort, not a delivery ACK. Prior callback side effects/results may already have happened;
retirement is not rollback and an earlier result frame is not proof of complete
log delivery. The native adapter integration must be validated separately.

Ordinary EOF/shutdown stops admission on both outputs and concurrently flushes
already-admitted data. It does not wait for active user callbacks; if raw stderr
is still blocked after the one-second tail the runner does not exit successfully.
An explicit user `process.exit`, a signal or another fatal error can still cut
output short. This guard is not a durable logging protocol or receiver ACK.

This is **not** an OS-wide stderr or RSS bound: direct fd writes (`fs.writeSync`,
`fs.write`), writes using an earlier captured native method, `.end(chunk)`, replaced
methods, native addons and escaped descendants are outside the `.write` guard.
The code assumes normal initial UTF-8 stderr before user imports; subsequent
standard setDefaultEncoding calls are tracked. Synchronous OS writes, a blocked
event loop, kernel stalls and parent SIGKILL cannot be interrupted by JS timers.
Real Windows pipe/TTY behavior, Node 24, real SDK and Rust integration remain
unverified. Node 22.16 POSIX pipe tests are local evidence only.

`diagnostic-output.test.mjs` exercises admission, native drain/cork, immutable
views, encodings, callbacks, error handling and deadlines. The real runner tests
pause/resume the stderr pipe, flood raw stderr and redirected stdout, test EPIPE,
flush and a real 30-second stall. Functions-shaped callbacks are test code, not
Firebase SDK functions. The platform-copy test uses a never-executed native
placeholder and checks that the diagnostic module ships with the runner.
