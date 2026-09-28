# Functions trigger option resolution (local runner)

The Node runner must announce the runtime values of the trigger options it
supports, not their deployment-expression strings. This change extends the
single-read `.value()` resolver used by endpoint options. The method is obtained
once per consumed option and called with its original receiver. No `toString`,
`toJSON`, coercion, asynchronous evaluation or recursive expression evaluation
is used to decide routing or retry settings. Literal strings are not rewritten
as URLs, and percent escapes and wildcard patterns remain literal data.

## Announced values

| Trigger | Consumed fields |
|---|---|
| Gen1 endpoint and legacy Firestore/Storage/PubSub | `resource` resolves before the existing resource parser. |
| Gen2 Firestore | `database`, `eventFilterPathPatterns.document`, or fallback `eventFilters.document`; a valid selected pattern does not evaluate the unused fallback. |
| Gen2 Storage / PubSub | `bucket` / `topic`. Existing absent-bucket behavior and topic projection are retained. |
| Eventarc and Firebase Alerts | `channel` and own enumerable exact filter values; empty exact values and literal `__proto__`/`toJSON` keys remain strings. |
| Schedule | `schedule`, `timeZone`, and the five retry fields below. Retry is derived from the resolved `retryCount`. |
| Task Queue | `maxAttempts`, `maxRetrySeconds`, `minBackoffSeconds`, `maxBackoffSeconds`, `maxDoublings`, `maxConcurrentDispatches`, `maxDispatchesPerSecond`. |

Literal null/undefined/SDK ResetValue retain default/unset behavior for optional
values and numeric configuration. An expression returning null/undefined does
not establish a default and is rejected. A null exact-match filter is not
silently dropped. Values must be strings or finite numbers of the appropriate
kind. Existing numeric range/count conversion remains the native parser's job;
this change neither asserts cloud quota limits nor changes native rounding.
Task fractional backoff seconds and dispatch rates, literal zero, and null/reset
numeric defaults remain representable.

Containers are ordinary option records, not expressions in their own right.
Numeric containers recognize only their declared fields; unknown keys are an
explicit local unsupported condition, not an instruction to drop a setting.
The finite scalar maps are detached, null-prototype, and frozen before the hello
is announced. Later exports cannot mutate an already described trigger's map.
A container's user-defined `toJSON` cannot replace the validated configuration
at wire serialization. Input metadata itself is not frozen or modified.

Malformed/unresolved settings isolate their export as named `ignored` entries.
Healthy siblings are still announced and can be invoked. Existing Gen1 malformed
resource strings retain their Firestore/Storage diagnostic classification.
This rejection policy is local, not a reproduction of every SDK/deploy error.

## Gen1 Schedule Duration aliases

The public Gen1 `ScheduleRetryConfig` uses `maxRetryDuration`,
`minBackoffDuration`, and `maxBackoffDuration`, whereas this repository's existing
native manifest parser consumes numeric `maxRetrySeconds`, `minBackoffSeconds`,
and `maxBackoffSeconds`. For Gen1 only, the runner maps these aliases to the
existing numeric seconds keys. It accepts a non-negative seconds literal such
as `"300s"` or `"0.125s"`, with up to nine fractional digits, or a synchronous
expression resolving to such a literal. Null/reset becomes a null seconds field.
An explicitly populated duration alias and seconds key together are ambiguous
and rejected, regardless of property order. Exponents, extra suffixes, whitespace,
negative durations, non-string durations, and non-finite conversion are rejected.

The numeric JSON protocol and the native Schedule parser's integer-second
conversion are unchanged. Preserving a fractional value in the hello does not
prove nanosecond-accurate scheduling or implement it in Rust. This is a local
adapter mapping, not a cloud observation.

## Explicitly unresolved: pre-rendered CEL

The pinned Gen1 `pubsub.schedule(Expression)` builder renders the expression to
a braced CEL **string** before storing it in metadata. That string no longer has
`.value()` to call. Braced CEL in schedule/timeZone is rejected as unsupported
rather than announced as a working cron. This change is not a CEL interpreter,
parameter prompt, deployment resolver or configuration/credential fetcher.
Direct runtime expressions that still expose `.value()` are covered; this is
not full support for every parameterized Gen1 schedule declaration.

## Verification boundary

The new tests execute the actual runner as a Node child, use framed IPC and
invoke callbacks. Three Task tests also use real loopback HTTP and verify the
exported wrapper is used rather than bypassed via `.run`. Metadata, parameter
objects and the HTTP Express layer are test doubles, not installed Firebase
packages. The source review includes pinned SDK definitions, but the SDK itself,
native trigger matching, actual writes/enqueue/retry, deployed ranges and
Node24 remain unexecuted here. No production request, permission, historical
receipt or binding is changed. Whole-parent acceptance remains separate.

```sh
node --test --test-concurrency=1 tools/runner-node/trigger-options-runner.test.mjs
```

Pinned primary inputs: `firebase-functions@7.3.2` `src/params/types.ts`,
`src/v1/providers/pubsub.ts`, `src/v1/function-configuration.ts`,
`src/v2/providers/scheduler.ts`, and `src/v1/providers/tasks.ts`.
Reference: https://firebase.google.com/docs/reference/functions/firebase-functions.scheduleretryconfig
Duration format: https://protobuf.dev/reference/protobuf/google.protobuf/#duration

Not addressed: general CEL, multi-region expansion, unsupported routing fields
or cloud services, native range policy, process isolation for arbitrary option
evaluators, full Functions SDK/native integration and final-artifact replay.
