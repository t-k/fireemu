# Node runner HTTP admission (local receiver contract)

This contract supplements the daemon's own admission and the IPC receiver; it is
not Firebase quota/concurrency parity and does not complete a compatibility parent.

## Order and authentication

The Node `request` / `checkContinue` listener validates the per-runner proxy
capability **before calling Express or reading/decompressing/parsing the body**.
Missing runner configuration is 500; a missing/wrong capability is 403; shutdown
is 503. Rejected connections are marked `Connection: close`, without an application
body drain. `100 Continue` is sent only after both authentication and reservation.
The accepted request's capability is removed from `headers` and `rawHeaders`.
This is a trusted local-proxy boundary, not isolation from code in the same process.

## Finite pending HTTP capacity

Each runner admits at most **1,024 pending HTTP requests** and reserves at most
**64 MiB of decoded body capacity** across parsing, queueing and execution.
The existing per-request parser limit remains **32 MiB**. For identity bodies with
Content-Length the reservation uses that length; a chunked/encoded body reserves
the full 32 MiB before parsing. It may shrink after the parser's verify callback
has an actual decoded Buffer. Thus at most two not-yet-decoded unknown-size bodies
can hold the full reservation at once. Empty requests still consume one count.

Exhaustion returns a local **503 before parsing/callback execution**. There is no
internal retry, waiting queue for rejected input, process retirement, or quota
extension. Known oversized body lengths are rejected with 413. Header/length errors
are rejected before admission. Limits are fixed at the runner entrypoint, not read
from caller payloads or environment. Unit tests instantiate smaller limits directly.

The reservation is held until the response terminates **and** any route execution
(including its per-function environment queue) settles. In particular, a closed
client cannot replenish capacity while its callback continues or its canceled
request still occupies the queue. A callback that returns before ending the response
also holds capacity. Parser failures, route mismatch and pre-dispatch disconnect
release once the response terminates. Each lease releases exactly once; releasing
an older lease cannot release a newer request. A rejected request never executes
its callback; earlier side effects are not rolled back.

## Limits of the claim

64 MiB is a logical reservation, **not an RSS/process/socket bound**. Parsed JSON
objects, parser copies, headers, compression working buffers, response bodies,
user-held references after callback completion, raw stderr, unrelated IPC memory,
OS queues and idle/unauthenticated connections are outside it. This does not add a
body-receive deadline or cancel a running Promise/synchronous user code. A stuck
callback retains its capacity; it is not declared canceled or safely retryable.
Node's existing server timeouts and the daemon remain separate layers.

Content-Length describes the identity input; encoded/unknown bodies are charged
conservatively until the existing parser provides the decoded Buffer. This can
reject otherwise individually valid requests under local contention. This policy
is intentionally separate from deployment concurrency and the daemon's decisions.

## Evidence and next acceptance steps

The tests use real Node runner processes and HTTP sockets, but the Express/body
parser and Firebase metadata are deliberately small test doubles. Gzip decoding
uses Node zlib in the fixture. `http-admission.test.mjs` verifies lease accounting,
error/release order and header policy; `http-admission-runner.test.mjs` verifies
actual pre-parser authentication, Expect handling, parser hooks, 1,024 concurrent
callbacks, early-ended responses and queued-disconnected requests. Installed
Express 4/5, Firebase SDK, Node 24 and native daemon integration still need execution.
The existing exact-size/rawBody contract and normal HTTP/Tasks/Blocking behavior
must be checked against those real dependencies before parent acceptance.

Primary references:
- https://nodejs.org/download/release/v22.16.0/docs/api/http.html#event-checkcontinue
- https://expressjs.com/en/4x/api/express/
