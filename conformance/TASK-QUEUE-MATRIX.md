# Task queue functions compatibility matrix

The TASK-QUEUE-FUNCTIONS parent covers Node.js v2 `onTaskDispatched` functions and the Cloud Tasks queue behind each one: admission by `createTask`, deduplication by task name, `scheduleTime`, `dispatchDeadline`, the HTTP request a function receives, retries and backoff, and the rate and concurrency limits of a queue. Its status is `COMPAT_VERIFIED` (`spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json`): the program, the recorder and the judge exist, two production recordings were made on 2026-11-11 (230 recorder requests each, observation complete, no finding), and the conditions marked verified below are the ones whose cases agree between the two runs and between fireemu's strict profile (with `productionExact`) and both runs, apart from the known differences the comparison files list. The record was approved by an independent closure review and a delta review.

The program (`conformance/src/task-queue-production/corpus.manifest.json`) has 122 steps. The recorder deploys eight task queue functions with the pinned firebase-tools to the events sandbox, sends the steps to the queues the deploy made, reads the deliveries from Cloud Logging, and deletes its queues and functions. Queue ids cannot be created again for days after a delete, so each run suffixes its function ids with six hexadecimal digits of its run id.

| Condition | Evidence kind | Program steps | Production |
| --- | --- | --- | --- |
| create-answer-shape | Production parity | 3 | Verified: two recordings, strict matches (known differences listed) |
| create-errors-shape | Production parity | 41 | Verified: two recordings, strict matches (known differences listed) |
| task-id-validation | Production parity | 45 | Verified: two recordings, strict matches (known differences listed) |
| dedup-live | Production parity | 6 | Verified: two recordings, strict matches (known differences listed) |
| dedup-after-completion | Production parity | 4 | Verified: two recordings, strict matches (known differences listed) |
| dedup-window-expiry | Production parity | - | Not compared (reason in the record) |
| schedule-time-boundaries | Production parity | 47 | Verified: two recordings, strict matches (known differences listed) |
| schedule-delay-and-eta | Production parity | 2 | Verified: two recordings, strict matches (known differences listed) |
| dispatch-deadline | Production parity | 45 | Verified: two recordings, strict matches (known differences listed) |
| body-and-header-limits | Production parity | 4 | Verified: two recordings, strict matches (known differences listed) |
| dispatch-envelope-headers | Production parity | 4 | Verified: two recordings, strict matches (known differences listed) |
| dispatch-envelope-body | Production parity | 5 | Verified: two recordings, strict matches (known differences listed) |
| task-name-generation | Production parity | 1 | Verified: two recordings, strict matches (known differences listed) |
| queue-config-mapping | Production parity | 8 | Not compared (reason in the record) |
| retry-on-status | Production parity | 2 | Verified: two recordings, strict matches (known differences listed) |
| retry-backoff-schedule | Production parity | 2 | Verified: two recordings, strict matches (known differences listed) |
| retry-limits | Production parity | 3 | Verified: two recordings, strict matches (known differences listed) |
| max-concurrent-dispatches | Production parity | 9 | Verified: two recordings, strict matches (known differences listed) |
| max-dispatches-per-second | Production parity | 8 | Not compared (reason in the record) |

The burst probe of 2026-11-13 (run f7e5c776424f470a; 120 tasks due at one instant on a rate-1 queue) started 10 tasks within 214 ms and then one per second; the queue read back `maxBurstSize` 10. The strict profile now starts such a queue with 10 tokens; rate 500 uses production's read-back burst of 100; other rates are unrecorded. The closure record still marks the condition NOT_COMPARED until the comparison is recorded.
| delete-task | Production parity | 6 | Verified: two recordings, strict matches (known differences listed) |
| local-controls | Fireemu-only | - | Verified by local tests (named in the record) |
| final-artifact-regression | Gate | - | Verified: release run R38 |
| closure-review | Gate | - | Verified: closureReview |

In the emulator profile, deleting a pending task returns `200 {"res":"OK"}` and prevents its dispatch; deleting a missing task returns 404. A task that was already dispatched can be deleted once with the same `200` (firebase-tools 15.28.2 keeps every enqueued name until its first delete); a second delete returns 404. The plain-text 404 and 409 answers are `text/plain; charset=utf-8` in fireemu and `text/html; charset=utf-8` in firebase-tools, with identical bodies (declared difference). GET and PUT on a task route return the official emulator's Express 404.

Reading the table: `Verified` is derived by `conformance/src/task-queue-production/closure-evidence.mjs` from `conformance/task-queue-production-run-comparison.json` and the two `task-queue-production-strict-vs-pass-N.json` files (no mismatch, no unknown, every claimed timing inside its tolerance). `Not compared` conditions are not claimed: the queue settings are read with the management API that neither fireemu nor the official emulator serves, the rate limit was never held back by the program's pacing, and the reuse window's expiry was not observed. The known differences cite coordinator rulings 3 and 6 (the function URL and path, the OIDC token and Cloud Run's platform headers, the queue management API reads). The official-emulator columns of the HOSTING matrix are absent on purpose: this parent compares the strict profile with production, and the `emulator` profile makes no production claim (it never refuses more than firebase-tools 15.28.2).

Excluded from the parent: deployment parity beyond the queue settings, the queue management API as an API, Gen1 task functions, Python task functions (FUNCTIONS-PYTHON owns their Tasks row), `TaskOptions.uri`, the value of the OIDC token, delivery order across tasks, exact timing, and scaling and quota.
