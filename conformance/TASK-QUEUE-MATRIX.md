# Task queue functions compatibility matrix

The TASK-QUEUE-FUNCTIONS parent covers Node.js v2 `onTaskDispatched` functions and the Cloud Tasks queue behind each one: admission by `createTask`, deduplication by task name, `scheduleTime`, `dispatchDeadline`, the HTTP request a function receives, retries and backoff, and the rate and concurrency limits of a queue. Its status is `IMPLEMENTING` (`spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json`): the program, the recorder and the judge exist, and no production observation has been made, so no condition is verified and no row below claims a match.

The program (`conformance/src/task-queue-production/corpus.manifest.json`) has 86 steps. The recorder deploys eight task queue functions with the pinned firebase-tools to the events sandbox, sends the steps to the queues the deploy made, reads the deliveries from Cloud Logging, and deletes its queues and functions. Queue ids cannot be created again for days after a delete, so each run suffixes its function ids with six hexadecimal digits of its run id.

| Condition | Evidence kind | Program steps | Production |
| --- | --- | --- | --- |
| create-answer-shape | Production parity | 3 | Not observed |
| create-errors-shape | Production parity | 5 | Not observed |
| task-id-validation | Production parity | 9 | Not observed |
| dedup-live | Production parity | 6 | Not observed |
| dedup-after-completion | Production parity | 4 | Not observed |
| dedup-window-expiry | Production parity | - | Planned (stage 2) |
| schedule-time-boundaries | Production parity | 11 | Not observed |
| schedule-delay-and-eta | Production parity | 2 | Not observed |
| dispatch-deadline | Production parity | 9 | Not observed |
| body-and-header-limits | Production parity | 4 | Not observed |
| dispatch-envelope-headers | Production parity | 4 | Not observed |
| dispatch-envelope-body | Production parity | 5 | Not observed |
| task-name-generation | Production parity | 1 | Not observed |
| queue-config-mapping | Production parity | 8 | Not observed |
| retry-on-status | Production parity | 2 | Not observed |
| retry-backoff-schedule | Production parity | 2 | Not observed |
| retry-limits | Production parity | 3 | Not observed |
| max-concurrent-dispatches | Production parity | 9 | Not observed |
| max-dispatches-per-second | Production parity | 8 | Not observed |
| delete-task | Production parity | 6 | Not observed |
| local-controls | Fireemu-only | - | Local evidence, not built |
| final-artifact-regression | Gate | - | After the recordings |
| closure-review | Gate | - | After the recordings |

Reading the table: `Not observed` means the step list exists and nothing has been sent. The official-emulator columns of the HOSTING matrix are absent on purpose: this parent compares the strict profile with production, and the `emulator` profile makes no production claim (it never refuses more than firebase-tools 15.28.2).

Excluded from the parent: deployment parity beyond the queue settings, the queue management API as an API, Gen1 task functions, Python task functions (FUNCTIONS-PYTHON owns their Tasks row), `TaskOptions.uri`, the value of the OIDC token, delivery order across tasks, exact timing, and scaling and quota.
