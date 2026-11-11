# TASK-QUEUE-FUNCTIONS recording

Production evidence for Node.js v2 `onTaskDispatched` functions and the Cloud Tasks queue behind each one. The parent is `IMPLEMENTING` (`spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json`): the program, the recorder and the judge exist, and nothing has been observed in production yet.

## Parts

- `plan.mjs`: names, pins and limits. The eight queue roles and the settings each declares. A function id is its role plus six hexadecimal digits of the run id, because Cloud Tasks refuses a queue id that was deleted within the last days.
- `corpus.mjs`: the program, 122 steps as data (create, delete and read tasks and queues of the run), with the pairwise admission table. `corpus.manifest.json` is its pinned form (`node corpus-manifest.mjs write`, then `oxfmt`).
- `../../task-queue-functions/functions/index.js`: the deployed fixture. Each delivery prints a `start` and an `end` frame (`TQ_FRAME {json}`) that the recorder reads from Cloud Logging. A task's own data scripts what the handler answers on each attempt.
- `record/`: the recorder. `run.mjs` (preflight, CLI dry run, one deploy, readbacks, the program, a bounded wait, cleanup and read-back of every name), `guard.mjs` (the allowlist of every request), `deploy.mjs`, `logs.mjs`, `judge.mjs`, `readback.mjs` (the later read-only A2), `main.mjs` and `bin.mjs` (the command line). It is adapted from the Python Functions check recorder.
- `record/world.mjs`: an in-memory model of the services, used by the tests. Its Cloud Tasks follows the documented rules; it is not an observation of production.

## Tests

```sh
cd conformance
node --test src/task-queue-production/*.test.mjs src/task-queue-production/record/*.test.mjs
```

No test sends a request to a Google service. The discovery and fixture tests need the conformance dependencies (`pnpm install --frozen-lockfile`).

## Running a recording

A recording is sent only by the coordinator, after a review of the frozen packet. `bin.mjs` refuses to send without `--send` and the digest of the packet it was reviewed as (`--expect-digest`). A run writes a private journal, a result file and the CLI logs into its run directory; these hold project numbers and are never committed.
