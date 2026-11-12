# TASK-QUEUE-FUNCTIONS recording

Production evidence for Node.js v2 `onTaskDispatched` functions and the Cloud Tasks queue behind each one. The parent is `IMPLEMENTING` (`spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json`): the program, the recorder and the judge exist, and two production recordings were made on 2026-11-11.

## Parts

- `plan.mjs`: names, pins and limits. The eight queue roles and the settings each declares. A function id is its role plus six hexadecimal digits of the run id, because Cloud Tasks refuses a queue id that was deleted within the last days.
- `corpus.mjs`: the program, 122 steps as data (create, delete and read tasks and queues of the run), with the pairwise admission table. `corpus.manifest.json` is its pinned form (`node corpus-manifest.mjs write`, then `oxfmt`).
- `../../task-queue-functions/functions/index.js`: the deployed fixture. Each delivery prints a `start` and an `end` frame (`TQ_FRAME {json}`) that the recorder reads from Cloud Logging. A task's own data scripts what the handler answers on each attempt.
- `record/`: the recorder. `run.mjs` (preflight, CLI dry run, one deploy, readbacks, the program, a bounded wait, cleanup and read-back of every name), `guard.mjs` (the allowlist of every request), `deploy.mjs`, `logs.mjs`, `judge.mjs`, `readback.mjs` (the later read-only A2), `main.mjs` and `bin.mjs` (the command line). It is adapted from the Python Functions check recorder.
- `project.mjs`, `publish.mjs`: the comparable projection of a recording (identities masked to forms, times reduced to their form) and the command that writes it (`TQ_PROJECT_NUMBER` in the environment, never printed; it refuses a file with a twelve or thirteen digit number). The unmasked result file is private and never committed.
- `compare.mjs`, `known-differences.mjs`, `compare-cli.mjs`: the case-by-case comparison (structure verdicts, timing by tolerance, concurrency properties) and the known differences, each citing a coordinator ruling. `local.mjs` replays the program against a real fireemu process (`FIREEMU_BIN=... node local.mjs --profile strict --out <new file>`).
- `closure-evidence.mjs`: derives the conditions' status and the comparison digests of the closure record from the committed files (`--check`, `--write`).
- `../../task-queue-production-*.json`: the two masked recordings, the committed local replay, and the three comparisons (run against run, strict against each run).
- `record/world.mjs`: an in-memory model of the services, used by the tests. Its Cloud Tasks follows the documented rules; it is not an observation of production.

## Tests

```sh
cd conformance
node --test src/task-queue-production/*.test.mjs src/task-queue-production/record/*.test.mjs
FIREEMU_BIN=<fireemu binary> node --test src/task-queue-production/strict-replay.test.mjs
```

The replay test is skipped without `FIREEMU_BIN`; it starts one fireemu process (strict, `productionExact`) and takes about a minute.

No test sends a request to a Google service. The discovery and fixture tests need the conformance dependencies (`pnpm install --frozen-lockfile`).

## Running a recording

A recording is sent only by the coordinator, after a review of the frozen packet. `bin.mjs` refuses to send without `--send` and the digest of the packet it was reviewed as (`--expect-digest`). A run writes a private journal, a result file and the CLI logs into its run directory; these hold project numbers and are never committed.

## The committed comparison files

The three comparison files (`../../task-queue-production-run-comparison.json` and `...-strict-vs-pass-{1,2}.json`) carry `kind: "task-queue-comparison-v1"` and are derived by `compare-cli.mjs`. They are reformatted by `oxfmt` after being written, so they are not byte-identical to the tool's output; `published.test.mjs` rebuilds them from the committed projections and compares the parsed values, which is what a reviewer should compare. The first delivery of a case is compared by its lateness after the task's ETA (`lateMs`), each retry gap within the tolerance, and the answer by its layout (content type, style and field order) as well as its content. `release-replay.mjs` and `release-judge.mjs` are the release run R38: the judge takes timing as a tolerance (twice the committed one) and requires the same cases, structure and parts as the committed files.
