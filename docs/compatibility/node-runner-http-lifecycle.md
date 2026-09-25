# Node runner HTTP response lifecycle

This is a local runner contract, not production Firebase parity or native/SDK
acceptance. HTTP, task HTTP and Blocking Auth callbacks share the same process;
local secrets (or the inspector) serialize their function environments.

## Termination and callback lifetime

`trackHttpResponse` starts observing `ServerResponse` **before** environment queue
admission. It latches `finish`, `close` and `error`, checks `destroyed` and
`writableFinished`, and removes only its own listeners. Waiting after a previously
observed close therefore cannot strand the queue. `writableEnded` prevents a new
callback from starting but is not proof that the response finished writing.
Request-body completion, `IncomingMessage.close` and `req.destroyed` are not used
as response-abandonment signals; fully received requests remain valid.

At actual callback entry the response is checked again. A queued request whose
response is already closed/ended is not started. This is a defensive **local
policy**, not a claim about production Task/HTTP cancellation or exactly-once
execution. Once callback code is running, its returned Promise is awaited even
if the response closes. We do not race it against close and restore/reassign
secrets while that Promise still uses them. Conversely, a callback that returns
before finishing its response retains the environment until response termination.
After callback settlement and response termination, the next queued invocation
can start. Non-secret/non-inspector calls keep the existing concurrency behavior.

A pending callback Promise, synchronous infinite user code, queued closure memory,
raw stderr and global process side effects are not bounded by this change. Native
HTTP admission/timeouts and process supervision remain separate. A client closing
a connection does not roll back earlier side effects or establish data cleanup.

## Blocking serialization and errors

Blocking Auth response materialization/validation occurs within the same selected
function environment as `fn.run`. User `toJSON`/getter evaluation is not deferred
until that environment has been restored (or reused by a different function).
The existing immutable validated snapshot is what is sent. If the response has
closed while awaiting the callback, its result is not materialized or sent.

Failure conversion, diagnostics and error publication execute in the selected
environment too. A closed/ended response gets no additional reply; after headers
have been sent a failed response is destroyed rather than passed to a success
middleware continuation. Ordinary pre-header failures remain HTTP 500 with the
fixed message; Blocking Auth continues to use its existing safe error classifier.
No new authentication route, retry, cleanup authority or production permission is
introduced. `finish` is Node's write completion, not the peer's receipt/application
ACK and never evidence that cloud resources were recovered.

## Evidence and remaining acceptance

`http-lifecycle.test.mjs` uses EventEmitter response models for event ordering and
listener ownership. `http-lifecycle-runner.test.mjs` launches the real `index.mjs`
with real Node HTTP sockets and real function callbacks, but its Express and
HttpsError adapters are test doubles. The callback-held secret is a synthetic
fixture value. Source package closure includes `http-lifecycle.mjs` explicitly.
Run both new tests and all existing runner/npm/Listen tests. Passing these does
not replace fixed Firebase SDK/Express, Node 24, native Auth/Functions integration,
real artifact/collector bindings, production-reference replay or independent review.
Prior immutable receipts and source digests are not relabeled by this change.

## Primary references

- Node 22.16 HTTP, ServerResponse `close`, `finish`, `writableEnded`,
  `writableFinished`, IncomingMessage `close`:
  https://nodejs.org/download/release/v22.16.0/docs/api/http.html
- Express error-handling guidance, errors after headers have been sent:
  https://expressjs.com/en/guide/error-handling/
