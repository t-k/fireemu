# Recorder ownership

`ownership.mjs` is a small Node library for any recorder that creates and deletes resources in a shared project. It answers three questions and nothing else: which names did this run issue, which may it delete, and which answers are still unknown. It has no framework and no transport code. The caller sends the requests and reports what came back. Existing recorders are not migrated; new ones use it.

Plain ESM, `node:fs` only. The ledger is JSONL, one file per run.

## The contract

```js
import { openOwnership, beginCreate, beginDelete, recordAnswer, recordRead,
         mayDelete, closureReport, closeOwnership } from "./shared/ownership.mjs";

const state = openOwnership({ path: ".runs/<run>/issued.jsonl", runId: "<run>" });

// 1. A create. The intent row is on disk (fsynced) when beginCreate returns: send only after that.
const ticket = beginCreate(state, { name: "topics/fe-<run>-a", transport: "rest" });
const answer = await send(); // yours
recordAnswer(state, ticket, { status, bodyReadable, transportError, operationPending });

// 2. A delete. beginDelete refuses a name this run did not create (OwnershipError, code not-owned).
const t = beginDelete(state, { name, transport: "rest" });
recordAnswer(state, t, answer);

// 3. An unknown answer is settled only by a direct GET of that exact name.
recordRead(state, { name, transport: "rest", answer: { status, bodyReadable, bodyName } });

// At the end of the run.
const { closureReady, reasons, details } = closureReport(state); // details: what each unsettled name waits for, and why
```

Report every answer with what you observed: `status` (HTTP; map a gRPC code to its HTTP equivalent: OK 200, ALREADY_EXISTS 409, NOT_FOUND 404, INVALID_ARGUMENT 400, UNAVAILABLE 503, DEADLINE_EXCEEDED 504), `bodyReadable: true` only when the body was read (an empty body is readable; leave it out and the answer is unknown), `transportError` for a timeout, reset or refused connection, and `operationPending: true` for a long-running operation you have not read as done. `bodyName`, when given on a GET, must equal the name asked for.

## What the library decides

- **Issued names.** Each create or delete is two rows: the intent, fsynced before the request is sent, and the answer, fsynced after it, each with the name, the transport and the answer class (`ok`, `conflict`, `notFound`, `refused`, `unknown`). A direct GET is a row too, and a refused delete is an audit row. A process that dies between the two rows leaves an intent with no answer; `openOwnership` on the same file turns it into an unknown answer (`no-answer`) and writes that down. A ledger row of another run makes `openOwnership` refuse: a run never adopts another run's names. A torn last line is dropped and counted.
- **Delete guard.** A name may be deleted only if this run's own create of it answered 2xx, or answered unknown and a later direct GET showed the name. A 409, a 404 or another 4xx on a create never makes a name ours, and a GET alone never does. The fact outlives this run's own delete, so deleting a deleted name again (a 404 probe) is allowed. A delete is never sent again after an unknown answer, even if a GET then shows the name (`unknown-delete-not-resent`): the name stays owned and a later cleanup run settles it.
- **Unknown answers.** A transport error, an unreadable body, a status below 200, a 3xx, a 5xx or a pending operation, on a create or delete, is unknown. Until a direct GET settles the name, `beginCreate` and `beginDelete` refuse it (`unsettled`). Only positive evidence settles at once: a GET showing the name settles an unknown create as ours, and an unknown delete as still there. A GET that finds nothing settles only after `settleAbsentAfterMs` (default 10 minutes, the owner's A2 read-back) from the unknown answer, because until then the request may still take effect or the read may be stale; an earlier absent GET is recorded and changes nothing (`closureReport().details` names the time it can settle). A GET that is itself unknown settles nothing.
- **Closure.** `closureReady` is false while any request is in flight, any unknown answer is unsettled, any name this run created is not yet deleted (a delete that answered 2xx or 404), or **any DELETE ever answered unknown, even one a GET settled**. The last rule is the owner's: the answer to that delete was never seen.

## What it does not do

Names must be unique to the run (put the run id in them); the library cannot tell a foreign resource that happens to carry the name of one whose create timed out. A deliberate probe of a name this run never created (a "delete of a missing object" scenario) is not a cleanup: issue it outside the ledger, with a name that cannot exist. Retries, backoff, list-based cleanup and the cost budget stay with the recorder.

Tests: `ownership.test.mjs` (rules), `ownership.property.test.mjs` (600 fixed-seed generated scripts over answer classes, effects and noise), `ownership.replay.test.mjs` (real recorded answers from PUBSUB, Cloud Scheduler and FE v5; `fixtures/ownership-replays/extract.py` derives the fixtures).
