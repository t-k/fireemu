# Recorder ownership

`ownership.mjs` is a small Node library for any recorder that creates and deletes resources in a shared project. It answers three questions and nothing else: which names did this run issue, which may it delete, and which answers are still unknown. It has no framework and no transport code. The caller sends the requests and reports what came back. Existing recorders are not migrated; new ones use it.

Plain ESM, `node:fs` only. The ledger is JSONL, one file per run. Names must be unique to the run (put the run id in them): that is a precondition, not a courtesy.

## The contract

```js
import { openOwnership, beginCreate, beginDelete, recordAnswer, recordRead,
         acceptUnconfirmed, mayDelete, closureReport, closeOwnership } from "./shared/ownership.mjs";

const state = openOwnership({ path: ".runs/<run>/issued.jsonl", runId: "<run>" });

// 1. A create. The intent row is on disk (fsynced) when beginCreate returns: send only after that.
const ticket = beginCreate(state, { name: "topics/fe-<run>-a", transport: "rest" });
const answer = await send(); // yours
recordAnswer(state, ticket, { status, bodyReadable, transportError, operationPending });

// 2. A delete. beginDelete refuses a name this run did not create (OwnershipError, code not-owned).
const t = beginDelete(state, { name, transport: "rest" });
recordAnswer(state, t, answer);

// 3. An unknown answer is settled only by a direct GET of that exact name that shows it.
recordRead(state, { name, transport: "rest", answer: { status, bodyReadable, bodyName } });

// 4. After your own delete answered 2xx, read the name back with a GET: it is settled only by a 404.
// 5. Only the coordinator accepts an unconfirmed create, with the owner-ledger line that says so.
acceptUnconfirmed(state, name, "owner ledger 901: run <run>, name <name>, reads <n>");

// At the end of the run.
const report = closureReport(state); // closureReady, reasons, unknownAnswers, absentUnconfirmed, coordinatorNote
closeOwnership(state);
```

## How to report what you saw

- `status` is the HTTP status. Map a gRPC code to its HTTP equivalent: OK 200, ALREADY_EXISTS 409, NOT_FOUND 404, INVALID_ARGUMENT 400, PERMISSION_DENIED 403, UNAUTHENTICATED 401, UNAVAILABLE 503, DEADLINE_EXCEEDED 504, **CANCELLED 499**. A 408 and a 499 are unknown, not refusals: the call may have been applied after it left.
- `bodyReadable: true` only when the body was read (an empty body is readable; leave it out and the answer is unknown).
- `transportError` for a timeout, reset or refused connection.
- `operationPending: true` only when you stop polling a long-running operation that is not done.
- A GET counts as **present** only when `bodyName` is given and equals the name asked for. A 2xx without `bodyName`, or with another, is unknown.

### A 2xx means "this run created it" only when the request cannot overwrite

The library takes a create that answered 2xx as made by this run. That holds when a second create of the same name fails: Pub/Sub topic and subscription PUT, Cloud Scheduler, Eventarc (409 on exists), a GCS upload with `ifGenerationMatch=0`. It does not hold for a plain PUT, a Firestore `set`, or a GCS upload without a precondition: those overwrite, and a 2xx would then claim a resource this run did not create. For such a request, send the create-only precondition, or report the answer as unknown and settle it with an own GET.

### Long-running operations

Keep the ticket open while you poll the operation. When it is done, call `recordAnswer` once: with status 200 if it finished without error, or with `operation.error.code` mapped to HTTP (ALREADY_EXISTS 409, and so on). Use `operationPending: true` only when you stop polling before it finishes: the effect on the name is then unknown, and the name is settled only by an own GET.

### One request that makes several names

A deploy, a CLI call or a batch may create several names at once (a function, its schedule job, a topic, a service). Call `beginCreate` for every name it will derive before you start it, then `recordAnswer` once per name, from what you can read for that name. An exit code of 0 is not a 2xx for each name: report `unknown` (a transport error, or `operationPending`) for any name you did not read.

### Lists are never a 404

A name missing from a list, or from page N of one, is not an absent GET and must never be passed to `recordRead`. A list may find candidates (the real PUBSUB cleanup found a timed-out topic that way); each candidate then gets a direct GET of its own, and that goes through `recordRead`.

## What the library decides

- **Issued names.** Each create or delete is two rows: the intent, fsynced before the request is sent, and the answer, fsynced after it, each with the name, the transport and the answer class (`ok`, `conflict`, `notFound`, `refused`, `unknown`). A direct GET is a row too, and a refused delete is an audit row. The first row of a ledger is `open`: it records the settle delay. A process that dies between the intent and the answer leaves an intent with no answer; `openOwnership` on the same file turns it into an unknown answer (`no-answer`) and writes that down. A ledger row of another run makes `openOwnership` refuse: a run never adopts another run's names. A torn last line is dropped and counted.
- **Delete guard.** A name may be deleted only if this run's own create of it answered 2xx, or answered unknown and a later own GET showed it. A 409, a 404 or another 4xx on a create never makes a name ours, and a GET alone never does. The fact outlives this run's own delete, so deleting a deleted name again (a 404 probe) is allowed. A delete is never sent again after an unknown answer, even if a GET then shows the name (`unknown-delete-not-resent`): the name stays owned, and it is never created again in this run (`unknown-delete-not-reused`).
- **A confirmed create that reads 404.** A create confirmed by a 2xx whose name then reads 404, or whose own DELETE answers 404, is not settled in the run: a read-after-write lag can hide a live resource. The name stays owned (`owned-not-deleted`, plus `confirmed-create-reads-404`), and only this run's own DELETE answered 2xx, followed by a 404 read, or the coordinator's A2 read-back settles it. A new confirmed create of the name starts without that 404.
- **A delete settles with a read-back.** After this run's own DELETE answered 2xx (or its operation read done, reported as a 200), the name is `deleted-unverified` until an own GET reads it as 404. A GET after the delete that shows the name makes it `deleted-but-present`; the last read counts. A read before the delete, an unreadable read, and a probe DELETE answered 404 do not count.
- **Unknown answers.** A transport error, an unreadable body, a status below 200, a 3xx, a 5xx, a 408, a 499 or a pending operation, on a create or delete, is unknown. Until it is settled, `beginCreate` and `beginDelete` refuse the name (`unsettled`).
  - **An unknown create** is settled only by an own GET that shows the name; the name is then ours. **A GET that finds nothing never settles it, however late.** The request may still take effect (production showed a create that timed out still present 40 minutes later). The absent reads are kept as evidence, the name is reported as `unknown-create-absent-unconfirmed`, and `closureReady` stays false. `report.coordinatorNote` then says the coordinator must accept the name or run a recovery.
  - **An unknown delete** is sticky. An own GET that shows the name settles the question whether it is still there (the delete is still never re-sent); a GET that finds nothing is only evidence (`unknown-delete-absent-in-run`, `settled: false`). `closureReady` stays false either way: the answer to that delete was never seen. The only thing that closes it is the coordinator's separate A2 read-back, at least 10 minutes after the last request and outside this library; a later run on the same ledger cannot.
  - **Accepting an unconfirmed create.** The coordinator records an acceptance as an owner-ledger line naming the run, the names and the reads. `acceptUnconfirmed(state, name, ledgerRef)` carries that reference into the ledger: it refuses an empty or unusable reference (`bad-ledger-ref`), a name that is not an unsettled unknown create (`not-unconfirmed`), and a name no GET found missing after the settle delay (`absent-read-required`). It lets closureReady drop that name only; the name is never created again in this run, and the unknown answer stays in `unknownAnswers` (`settled-accepted`, with the reference) and in `accepted`.
  - Every unknown answer stays in `report.unknownAnswers` for the whole run, settled or not: name, action, ticket, reason, answer time, how it was settled, the absent reads (each marked `afterDelay` or not), `eligibleForA2At` (answer time plus the delay) and `requiresA2`. `details` is the unsettled part. `lastRequestAt` is the time of the last intent, answer or read, and `a2NotBefore` (that time plus the delay) is the earliest the A2 read-back may start; per-answer `eligibleForA2At` is earlier and is not a schedule.
- **Closure.** `closureReady` is false while any request is in flight, any unknown answer is unsettled, any name this run created is not yet deleted (a delete that answered 2xx), or any name this run deleted is not yet read back as 404 (`deleted-unverified`, `deleted-but-present`), or any DELETE ever answered unknown, even one a GET settled. A settled unknown create does not block closure, but `a2Required` is true whenever the run had any unknown answer: the A2 read-back precedes any close row.
- **The settle delay** is `settleAbsentAfterMs`, 10 minutes by default (the A2 read-back) and never less (`testOnlyAllowShortSettleDelay` exists for tests). It is written in the `open` row. A resume cannot change it: a different value is refused (`settle-delay-mismatch`), and with no value the ledger is resumed with the recorded one.
- **A failed write stops the state.** If a write or its fsync throws, the state is closed (`ledger-failed` for every later call), so a retry cannot write a second intent or bytes after a half row. Resume the file: a half row is dropped, and a whole intent with no answer becomes an unknown answer.
- **One writer.** `openOwnership` takes `<path>.lock` (the holder's pid) and refuses a second open (`ledger-locked`) while the holder runs. A lock whose process is gone is taken over, which is how a crashed run is resumed. Same host only; a lock whose content is not a pid is never taken over.

## What it does not do

The library cannot tell a foreign resource that happens to carry the name of one whose create timed out; hence unique names. A deliberate probe of a name this run never created (a "delete of a missing object" scenario) is not a cleanup: issue it outside the ledger, with a name that cannot exist. On macOS `fsync` does not issue `F_FULLFSYNC`, so power-loss durability is not claimed. Retries, backoff, list-based cleanup, the cost budget and the A2 read-back stay with the recorder and the coordinator.

Tests: `ownership.test.mjs` (rules), `ownership.property.test.mjs` (600 fixed-seed generated scripts over answer classes, effects, late effects and noise, with a reference model and a world-safety property), `ownership.replay.test.mjs` (real recorded answers from PUBSUB, Cloud Scheduler and FE v5; `fixtures/ownership-replays/extract.py` derives the fixtures byte for byte, and the test checks the source digests when the private run records are present).
