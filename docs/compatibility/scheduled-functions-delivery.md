# Scheduled functions: delivery and retry, against production

SCHEDULED-FUNCTIONS is IMPLEMENTING (`docs/compatibility/scheduled-functions.md`). This page records what the second production delivery recording showed about how Cloud Scheduler hands a scheduled run to a function and retries a failed one, what the strict profile now does about it, and what is still different. Nothing here promotes a closure condition: the frozen inventory needs two recordings of each corpus and a comparison on the final artifact.

## The recording

Run `156715222b86ea44` (2026-10-05, sandbox project `fireemu-oracle-sbx`, region `us-central1`): one Firebase CLI deploy of five functions (three Gen2 `onSchedule`, two Gen1 `pubsub.schedule`; `conformance/scheduled-delivery/fixture`), two observation passes (a forced `:run` of every job, then six minutes of natural fires), 97 handler frames, 177 Cloud Scheduler execution entries and 17 pulled Pub/Sub messages, cleaned up and read back absent. Four extra REST jobs probed the retry rules. The public digest the local comparison reads is `conformance/scheduled-delivery/local/production-run2.json` (no project number, trace id or client address).

What production did, in the terms a handler sees:

- **Gen2.** Cloud Scheduler sends `POST /` with `x-cloudscheduler: true`, `user-agent: Google-Cloud-Scheduler`, `content-length: 0`, an OIDC `authorization` header, the job's **id** in `x-cloudscheduler-jobname` (`firebase-schedule-<name>-us-central1`) and the schedule time in `x-cloudscheduler-scheduletime`, written **in America/Los_Angeles with its offset** (`2026-10-05T01:41:00-07:00`) for a UTC job and an Asia/Tokyo job alike. The SDK builds the event from those headers: `jobName` and `scheduleTime`, and a non-enumerable `context` getter. A handler that throws is answered 500 and the attempt is retried per the job.
- **Gen1.** The handler gets one argument, the context of the Pub/Sub message the job published: a 17-digit `eventId`, `resource` `{name: projects/<p>/topics/<job id>, service, type: type.googleapis.com/google.pubsub.v1.PubsubMessage}`, the message's publish time (milliseconds at most, trailing zeros dropped) as `timestamp`. The message has empty data and the attribute `scheduled: "true"`. A Gen1 handler that throws is not retried.
- **Time zones.** An omitted zone reads back as `UTC` for Gen2 and `America/Los_Angeles` for Gen1 (the Firebase CLI writes them).
- **Retry.** `retryCount: 4` (min 4 s, max 50 s, 2 doublings): five attempts at 0, 4.6, 13.2, 29.7, 48.2 s. `retryCount: 5` (defaults): six attempts at 0, 5.6, 16.3, 36.8, 77.3, 158.0 s. `retryCount: 0`: one attempt. A retry window with no count (`maxRetryDuration: 30s`, min 4 s, max 10 s): four attempts at 0, 4.6, 13.2, 23.7 s, the next being past the window. The occurrence's schedule time is the same on every attempt.
- **Refusals.** A job with `retryCount: 6` is refused (400, `invalid retry count. The retry_count must be a positive integer less than 5: invalid argument`) although 5 is accepted; a retry window of `20.5s` is refused (400, `retryConfig.max_retry_duration.nanos cannot be set: invalid argument`).
- **Timeouts and overlap.** A handler that outlasts its function timeout (100 s against 90 s) is answered 504 at 90 s and keeps running to its end; the next occurrence starts while it runs.

## What the strict profile does now

| Behaviour | Strict | Emulator profile |
|---|---|---|
| Gen2 delivery | the function's HTTP wrapper is called with the recorded headers (job id, Los Angeles time, empty body), so the SDK builds the event, the `context` getter, runs its init hook and maps a throw to 500 | unchanged: the handler is called directly with the job's resource name and a UTC time |
| Gen1 context | the Pub/Sub context above (17-digit id, topic, `PubsubMessage` type) | unchanged |
| Zone of a schedule that names none | Gen1: America/Los_Angeles; Gen2: UTC | UTC (or `scheduler.defaultTimeZone`) |
| Retry window with no count | retries until the window ends | the same (a retry model change, not a refusal; the official emulator never retries a scheduled function) |
| `retryCount` 6 or more, fractional `maxRetrySeconds` | refused at startup with production's message | accepted, as the official emulator accepts them (it creates no Scheduler job and reads no retry configuration of a schedule trigger) |

A manual run (`functions/{name}:run`) is Fireemu control, not Cloud Scheduler's run-now, and uses the same event shape as a scheduled one.

## What still differs

Unreproducible: the OIDC `authorization` header and the trace and forwarding headers. Not determined by the recording: the phase of an interval schedule (production anchors `every 1 minutes` to the job's creation instant with sub-second drift, and an `every 5 minutes` job ran off the five-minute boundary after forced runs; fireemu runs both on the minute and the boundary), and what a Cloud Scheduler run-now carries (the job's next schedule time; fireemu's manual run carries the current logical time). Not explained: the fourth gap of the `retryCount: 4` chain, about 18 s where the documented linear step gives 32 s. Not implemented: a Gen1 schedule does not create its topic or publish the message (empty data, `scheduled: "true"`) into the local Pub/Sub emulator, and no Cloud Scheduler job resource or execution log exists.

## Re-running the comparison

`conformance/scheduled-delivery/local/run-compare.mjs` runs the recorded fixture and a retry-probe fixture under both profiles with a pinned logical clock and prints one row per observation with a verdict per profile (`MATCH`, `DIVERGES`, `NOT_COMPARABLE`). It needs a fireemu binary (built with `RUSTC_WRAPPER=` so that no compiler cache is involved), a Node 22 and a `node_modules` holding firebase-functions 7.3.2. `local-delivery.test.mjs` runs the delivery rows end to end when `FIREEMU_BIN`, `FIREEMU_NODE` and `FIREEMU_DEPS` are set.

## Where each closure condition stands

The frozen inventory (`spec/compatibility/closure/SCHEDULED-FUNCTIONS.json`) has 25 conditions, 14 of them production-parity. Each production-parity condition needs two genuine recordings of its corpus and a comparison on the final artifact; so far the calendar corpus (8 cases, `conformance/scheduled-functions`) and the delivery corpus (this recording) have been recorded once each, and the first delivery attempt (run `e0ec2f416f5ea7e8`) was refused by Cloud Scheduler and is not a recording of the corpus. "Observed once" below means the case was exercised in one complete recording; it is not closure evidence.

| Condition | Kind | Cases | Observed once | Local comparison (strict) | What is left |
|---|---|---|---|---|---|
| declarations-v1-v2 | production-parity | 12 | 10: v1 and v2 declarations, omitted and explicit zone (v1 America/Los_Angeles, v2 UTC), options, retry options, attemptDeadline (180 s for a Gen2 job, none for Gen1), the job location without an App Engine app, the fractional retry duration refusal | the defaults are applied (zone); fireemu has no job resource to read back | omitted-versus-null-reset, SDK attemptDeadline versus the CLI timeout; the second recording |
| cron-grammar | production-parity | 13 | 3 (calendar: wildcard, named month and weekday, wrong field count) | the grammar tests | 10 cases not yet in a corpus; the second recording |
| groc-grammar | production-parity | 13 | 2 (calendar: every N minutes, ordinal weekday) | the grammar tests | 11 cases not yet in a corpus; the second recording |
| timezone-validation-defaults | production-parity | 6 | 6 (UTC, Asia/Tokyo, America/New_York, the v1 and v2 defaults, an invalid zone) | zones and defaults match (strict) | the second recording |
| next-occurrence | production-parity | 5 | 3 of the calendar cases | the calendar pins (`calendar_v5_pins.rs`) | the sparse and leap-day cases; interval phase (see above); the second recording |
| dst-calendar | production-parity | 4 | 3 (spring gap, fall fold, UTC control) | the calendar pins | a non-DST zone control; repeated-hour delivery is not shown by next-time metadata; the second recording |
| v2-http-delivery | production-parity | 9 | 9 | 8 rows MATCH; the OIDC and trace headers are not reproduced | the second recording; the headers |
| v1-pubsub-delivery | production-parity | 7 | 7 | the handler's context matches; the published message (empty data, `scheduled: "true"`) is not materialized | publish into the local Pub/Sub emulator; the second recording |
| forced-and-natural-invocation | production-parity | 4 | 4 | natural cadence spacing matches; the phase of an interval and a run-now's schedule time differ | decide the run-now question (Fireemu control is distinct); the second recording |
| retry-config-validation | production-parity | 8 | 7 (defaults, zero, the count boundary 0 to 6, min and max backoff, doublings, a retry window, the fractional window refusal) | strict refuses what production refused | the attemptDeadline boundary; the second recording |
| v2-retry-limits | production-parity | 6 | 5 | zero, finite count and duration-only chains match | count and duration together (never accepted by production yet); the second recording |
| v2-backoff | production-parity | 5 | 5 | first delay, doubling and the cap match; the linear step after the doublings differs (18 s recorded, 32 s modelled) | the second recording with other doubling counts, to find the formula |
| v1-two-stage-retry | production-parity | 4 | 2 (publish acknowledged while the handler fails; a failing Gen1 handler is not retried) | a Gen1 failure is attempted once | the Gen1 retry declaration; occurrence identity; the second recording |
| deadline-and-overlap | production-parity | 4 | 4 (a handler outlasting its timeout is answered 504 at the timeout and runs on; the next occurrence overlaps it) | fireemu also runs the handler to its end and allows overlap by default | the second recording |
| clock-config, clock-forward-boundaries, catch-up-policy, retry-delay-fairness, capacity-cursor, rewind-and-token-policy, manual-schedule, state-lifecycle | fireemu-only | 5, 6, 8, 4, 4, 5, 5, 5 | not applicable | VERIFIED locally before this work; their evidence is bound to the artifact and runner digests of that time | re-verify on the final artifact: the runner and the event shape of a manual run changed in the strict profile |
| overlap-policy | fireemu-only | 6 | not applicable | PENDING_LOCAL_VERIFICATION; production overlaps a running handler with the next occurrence, as the default does | the pending local verification; whether a pending retry suppresses the next occurrence under `skip` is unobserved |
| final-artifact-regression | closure-gate | 7 | not applicable | this comparison is the first strict-production comparison | two recordings, the exact frozen case set, the emulator-no-new-refusals proof, the workspace regression and the artifact and runner binding |
| closure-review | closure-gate | 2 | not applicable | not started | the independent review and the owner's promotion decision |
