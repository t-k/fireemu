# Listen full-refresh delivery and snapshot retention

The full-refresh implementation selects immutable document handles before sending responses. It encodes a document only after reserving an outbound channel slot. This bounds queued encoded responses, but the selected immutable handles and the payloads they keep alive remain proportional to the result size.

Consecutive change rows of one target are queued as one run of handles, a pointer per row, instead of one response-sized entry (168 bytes on aarch64) per row. The send loop expands a run one frame at a time. The selected handles are still the refresh's pinned snapshot, so the frames, their order, the CURRENT and NO_CHANGE boundaries, the resume tokens and the existence filters are unchanged. The [run-queue measurement](#run-queue-measurement) below compares the two queues.

## Reproducing the baseline

The ignored `streams::refresh_tests::measure_listen_initial_snapshot_delivery` test exercises the actual in-process Listen producer and receiver. It generates 100,000 documents with a 1,024-byte string payload each, uses two Tokio worker threads, and uses a 256-response channel. The fixture contains one unrelated document that is excluded from the query. The receiver discards each response after checking it instead of accumulating the complete result.

```sh
cargo test -p fireemu-adapter-grpc --release --lib --no-run
FIREEMU_LISTEN_MEASURE_DOCUMENTS=257 cargo test -p fireemu-adapter-grpc --release --lib measure_listen_initial_snapshot_delivery -- --ignored --nocapture
FIREEMU_LISTEN_MEASURE_DOCUMENTS=100000 cargo test -p fireemu-adapter-grpc --release --lib measure_listen_initial_snapshot_delivery -- --ignored --nocapture
```

Run the compiled test binary directly when measuring process peak RSS so compilation and Cargo do not contaminate the measurement. Apply a 6 GiB memory limit to the measurement process. The `listen_delivery_setup_done` record separates fixture construction from delivery. Measure process RSS externally and report setup and streaming samples separately, together with the process lifetime peak. Sampling is approximate; a phase's largest sample is not a guarantee that its instantaneous maximum was captured.

`first_add_micros` and `first_document_micros` are measured from immediately before sending AddTarget until the receiver obtains ADD and the first DocumentChange respectively. These are in-process channel latencies, not network gRPC latency. `complete_micros` ends at the final global NO_CHANGE. The harness checks document count, ADD-before-document ordering, CURRENT after all documents, and a matching token and read time on CURRENT and the final boundary. It drops the receiver and request sender and awaits producer completion.

The older `measure_listen_initial_snapshot_encoding` benchmark uses 20 KiB payloads and reports encoding latency. Its eager reference reconstructs an older implementation; it is not the baseline for this measurement.

## Why paths and a version are insufficient

`refresh_all` selects every target under one database read lock through `LocalBackend::with_listen_snapshot`. This captures the version, read time, database generation and token history consistently. `refresh_target_full` retains ordered immutable document handles, and later delivery reads those handles even if the store changes.

`FirestoreState::run_query_paths_with_stats` can select ordered paths without cloning ordinary document payloads. However, `get_at_shared` does not pin history. Store compaction advances a hard per-path capacity floor even when an active transaction refers to an older version. Restoring a database also replaces its generation and data.

For example, a refresh can select documents A and B, send A, then pause for a slow receiver. If writes compact B's selected version, or a restore replaces the database, looking B up later by path and version cannot reproduce its selected payload. The existing immutable handle can. Restarting, skipping B, emitting RESET, or failing that already selected refresh would change its frame sequence.

Adding a history pin would require an explicit decision about history limits, write admission and restore. It could also retain the entire old result while a receiver is stalled. Holding a read lock across sends would block writers, and a client that writes before it reads would wait on itself. Re-running the query per page from a cursor would let later pages see later writes. None of these is implemented.

The handles are the smallest pinned snapshot available without those changes: a handle shares its document with the store and costs one pointer, less than a selected path. A payload is retained beyond the store only when a write replaces a selected document before it is delivered, which any pinned snapshot must also retain. The target's known-document map, which every Listen target keeps for later diffs, remains proportional to the result in every design.

## Existing semantic checks

`streams::frame_identity_tests::listen_frames_match_the_recorded_transcripts` drives the real producer through 160 generated scenarios in each profile: query and document targets, `once` targets, removes, resumes with and without an expected count, foreign tokens, and commits landing while a snapshot is partly read. It hashes every frame and client action and compares the digests with `crates/fireemu-adapter-grpc/tests/fixtures/listen_frame_identity.txt`, recorded from the producer before the run queue. Map field order and the random bytes of strict tokens are canonicalized; which frames share a token is still compared. `full_refresh_queues_a_handle_per_snapshot_row` bounds the queue, `slow_client_mid_run_bounds_encoding_and_cancellation_releases_the_run` covers back-pressure and cancellation in the middle of a run, and `queued_runs_expand_to_the_rows_in_queue_order` is a property test of the expansion.

The adapter's stream tests also include `deferred_snapshot_rows_and_boundaries_survive_writes_deletes_and_restore`, `deferred_stream_keeps_snapshot_rows_before_current_during_writes`, and `slow_receiver_bounds_encoding_and_releases_snapshot_handles_on_drop`. They cover selected content and boundaries across changes, row ordering during writes, encoding backpressure, and cancellation cleanup. The measurement test complements these checks; it does not establish new production behavior.

## Measured baseline

One release run on Linux aarch64 with Rust 1.94.0 completed successfully. The VM had four CPUs and 8 GiB RAM; the container had a 6 GiB memory cap, no swap, and four CPUs. Other coordinated build and test jobs were paused during measurement. Release fat LTO was unchanged. These are one-run observations, not a latency distribution.

| Measurement | Result |
| --- | ---: |
| Generated documents | 100,000 |
| String payload per document | 1,024 bytes |
| Fixture setup | 750.374 ms |
| Receiver obtains ADD | 137.364 ms |
| Receiver obtains first DocumentChange | 137.365 ms |
| Receiver obtains final NO_CHANGE | 250.391 ms |
| Process lifetime peak RSS (`getrusage`) | 396,300 KiB |
| Setup sampled RSS peak | 325,096 KiB |
| Delivery and cleanup sampled RSS peak | 396,628 KiB |
| Container memory peak, including sampler | 416,075,776 bytes |

RSS was sampled from `/proc/<pid>/status` every 10 ms. Phase tagging changed when the setup marker was read, so phase attribution has scheduling and sampling uncertainty. The streaming phase includes producer cleanup and test teardown. Linux's sampled RSS and process high-water accounting differed slightly; they are reported independently. Subtracting the phase peaks would not establish a bound on retained snapshot memory.

The direct measurement command after building was:

```sh
FIREEMU_LISTEN_MEASURE_DOCUMENTS=100000 target/release/deps/fireemu_adapter_grpc-<build-hash> streams::refresh_tests::measure_listen_initial_snapshot_delivery --exact --ignored --nocapture
```

The harness passed its count, sequence, boundary and cleanup assertions. The 257-document smoke also passed. Focused release nextest ran six existing library tests successfully, with 742 tests skipped:

```sh
cargo nextest run --locked --offline -p fireemu-adapter-grpc --release --lib --profile pr -E 'test(deferred_snapshot_rows_and_boundaries_survive_writes_deletes_and_restore) | test(deferred_stream_keeps_snapshot_rows_before_current_during_writes) | test(slow_receiver_bounds_encoding_and_releases_snapshot_handles_on_drop) | test(listen_snapshot_selection_shares_store_document_identity) | test(snapshot_selection_defers_document_encoding_until_delivery) | test(resume)'
```

The resume filter selected the cross-backend issuance refusal test. Integration tests and recorded conformance replays were not run. There is no production implementation diff, failing-first runtime claim, or production mutation result. The original 3 GiB release build ended with a killed compiler; the unchanged build succeeded under 6 GiB with a measured container peak of 5,069,897,728 bytes and no OOM events. That build resource failure is separate from the measured Listen process.

No before/after improvement is claimed because the production implementation is unchanged. Exact bounded-memory paging remains unimplemented for the retention and restore reasons above.

## Extended TCP measurement protocol

The ignored integration test `measure_listen_network_delivery` uses a tonic client and server connected over loopback TCP. Both run in one process on two Tokio workers, so measured RSS includes the client, server, HTTP/2 buffers and fixture. It cannot be interpreted as server-only memory. Each process builds a fresh fixture through 500-document Commit requests and binds an OS-assigned port. The connection and fixture setup times are separate from AddTarget delivery.

`FIREEMU_LISTEN_MEASURE_DOCUMENTS` selects the fixture size (at least 257). `FIREEMU_LISTEN_MEASURE_RECEIVER` selects `normal` or `pause`; the latter waits two seconds after ADD and any scheduled writes before reading document responses. `FIREEMU_LISTEN_MEASURE_MUTATION` selects `none` or `write`; the write schedule updates the first 100 documents, deletes the final original document and creates one document. `FIREEMU_LISTEN_MEASURE_TERMINATION` selects `drain` or `cancel`. Drain verifies the complete ordered original snapshot, its boundaries, and the expected 102 subsequent changes when writes are enabled. Cancel drops the stream after the selected schedule. Both paths drop the client and await server shutdown; a task guard aborts the server on assertion failure.

Pausing application reads does not immediately stop HTTP/2 buffering. Sampled RSS during the pause is an observation, not proof of page-bounded memory. `cleanup_micros` measures client drops and awaited tonic server shutdown. The Listen producer is spawned separately without a retained join handle, so this metric does not measure producer termination or prove leak freedom; the producer could finish during test-runtime teardown. Existing library cancellation and shared-handle tests are separate evidence and should not be attributed to this network measurement.

Delivery timings start immediately before sending AddTarget on an established Listen stream. They exclude the initial Listen handshake. Write and slow-reader schedules include sequential Commit/GetDocument work, the explicit two-second pause where selected, and client decoding and validation before completion. They are application-observed scenario elapsed times, not isolated server latency. Cancellation reports zero received initial documents and null document/boundary timings; it is not a successful delivery of 100,000 documents. Large runs require an external whole-run timeout and memory limit because individual fixture Commit requests do not have local deadlines.

### TCP results

Six fresh-process runs used 100,000 documents each, a 1,024-byte string payload, two Tokio workers and unchanged release fat LTO. The Linux aarch64 VM had 8 GiB RAM and four CPUs; each measured container had a 6 GiB memory limit, no swap, two CPUs and a 180-second whole-run deadline. Fixture setup took 9.374–9.730 seconds. VM and filesystem caches were not reset between runs.

| Schedule | ADD (ms) | First document (ms) | Initial boundary (ms) | Process peak RSS (KiB) |
| --- | ---: | ---: | ---: | ---: |
| Normal 1 | 195.310 | 195.339 | 517.301 | 402,892 |
| Normal 2 | 144.474 | 144.491 | 399.351 | 401,376 |
| Normal 3 | 134.838 | 134.860 | 356.092 | 400,236 |
| Two-second pause | 159.607 | 2,170.985 | 2,371.641 | 401,772 |
| Write, then two-second pause | 131.758 | 2,137.007 | 2,357.112 | 402,700 |
| Two-second pause, then cancel | 135.629 | Not received | Not received | 401,812 |

All five draining runs verified every original document's name, order, revision and payload, followed by matching CURRENT and NO_CHANGE boundaries. The write run also verified the subsequent 100 updates, one deletion and one creation. Its scheduled Commit took 1.477 ms and GetDocument plus validation took 0.793 ms. The cancel run deliberately received zero document frames after ADD and did not validate a complete snapshot. Client drop and tonic shutdown took 0.117–0.267 ms across the six runs; this is not a measurement of detached producer termination.

Each process and container exited successfully. The largest container memory peak was 423,870,464 bytes, including the external sampler; all six containers recorded zero memory-limit and OOM events. RSS is the process lifetime high-water value from `getrusage`, including fixture construction. Ten-millisecond `/proc` samples separately tagged setup, delivery, pause, writes and shutdown, with phase-attribution uncertainty at marker receipt. These observations do not establish a memory bound or isolate server allocations.

Host load and the shared job registry were recorded at each run's start and end. On the host's 18 logical CPUs, the one-minute load average ranged from 2.750 to 4.551. Other native mutation and nextest jobs overlapped the series. Normal first-document observations ranged from 134.860 to 195.339 ms; three samples under changing load do not establish a stable latency distribution or a strict comparison with the earlier in-process run. No speedup or memory-reduction claim is made.

To reproduce a schedule after building the single integration binary, run it inside the stated memory limit with an external deadline:

```sh
cargo test --locked --offline -p fireemu-adapter-grpc --release --test listen_delivery_measurement --no-run
FIREEMU_LISTEN_MEASURE_DOCUMENTS=100000 \
FIREEMU_LISTEN_MEASURE_RECEIVER=pause \
FIREEMU_LISTEN_MEASURE_MUTATION=write \
FIREEMU_LISTEN_MEASURE_TERMINATION=drain \
timeout --signal=TERM --kill-after=5s 180s target/release/deps/listen_delivery_measurement-<build-hash> measure_listen_network_delivery --exact --ignored --nocapture
```

The integration harness's 257-document smoke and all eight receiver/mutation/termination combinations passed. All-target/all-feature clippy and formatting passed. One viable fixture-revision mutant was rejected by the document-content assertion; the unchanged and restored controls passed. This validates the measurement guard, not a production mutation campaign. A separate finite harness-schedule model checked 62 states for framing and harness-owned handle/server termination; it did not model the detached Listen producer. Recorded conformance replays were not run, and production behavior was not changed.

## Run-queue measurement

Five alternating release runs of the in-process measurement on macOS aarch64 (18 logical CPUs, Rust 1.94.0, unchanged fat LTO), 100,000 documents with a 1,024-byte payload. "Before" is the producer that queued one entry per row; "after" queues runs. Both binaries were built with the same command from their commits. Other build and test jobs were running; the one-minute load average was about 10. Peak RSS is `/usr/bin/time -l` maximum resident set size for the whole test process, including fixture construction.

| Run | Before peak RSS (bytes) | After peak RSS (bytes) | Before first document (ms) | After first document (ms) | Before final NO_CHANGE (ms) | After final NO_CHANGE (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 387,547,136 | 352,387,072 | 131.360 | 134.165 | 202.723 | 210.001 |
| 2 | 387,022,848 | 352,567,296 | 192.648 | 151.265 | 290.491 | 219.174 |
| 3 | 385,941,504 | 353,697,792 | 107.029 | 110.158 | 158.809 | 158.851 |
| 4 | 386,007,040 | 352,976,896 | 99.187 | 84.281 | 141.995 | 126.742 |
| 5 | 385,859,584 | 353,435,648 | 89.259 | 96.723 | 129.168 | 144.207 |

Peak RSS fell by 32.2 to 35.2 MB in every pair (about 9 percent of the process peak). Time to first document and to the final boundary overlap between the two and show no measurable change: selection, the diff and the known-document map still run in the same lock section before the first frame.

```sh
cargo test --locked -p fireemu-adapter-grpc --release --lib --no-run
FIREEMU_LISTEN_MEASURE_DOCUMENTS=100000 /usr/bin/time -l target/release/deps/fireemu_adapter_grpc-<build-hash> streams::refresh_tests::measure_listen_initial_snapshot_delivery --exact --ignored --nocapture
```

## Known-document map

Every Listen target keeps the `(document, version)` set it last delivered, to diff the next refresh against. That map lives as long as the target, so a large result costs its size once per target, and a full refresh used to rebuild it: every path of the result was cloned into a second map (five allocations per path) while the first was alive, even when nothing had changed.

Two changes, neither visible on the wire (the 320 recorded transcripts of `listen_frames_match_the_recorded_transcripts` are unchanged):

- A full refresh folds the result into the existing map in place. A key is created only for a document that enters the target; departures are found from a borrowed set only when the map and the result differ in size, and are reported in path order as before.
- The map stores one allocation per document, the collection and document ids joined by NUL, instead of a `DocumentPath`. Ids reject control characters, so the joined form orders exactly as the paths do (property `known_keys_order_as_paths_do`), and a key gives its path back for the removal frame.

### Known-map measurement

The ignored `streams::refresh_tests::measure_listen_repeat_full_refresh` test adds `FIREEMU_LISTEN_MEASURE_TARGETS` identical query targets over `FIREEMU_LISTEN_MEASURE_DOCUMENTS` documents (1,024-byte payloads), drops the initial rows, then forces three full refreshes of every target after unrelated commits while a thread samples the process RSS with `ps` every 5 ms. Three release runs each on macOS aarch64 (18 logical CPUs, Rust 1.94.0, unchanged fat LTO, load about 10), 100,000 documents; "before" is origin/main e8aad1d37 with the same test. RSS values are KiB. The sampler can miss the instantaneous peak.

| Targets | Measure | Before | After |
| ---: | --- | ---: | ---: |
| 1 | RSS after the target was added | 343,824-343,984 | 326,368-326,640 |
| 1 | peak RSS during the refreshes | 375,328-375,488 | 341,152-341,360 |
| 1 | three full refreshes (ms) | 636-794 | 253-344 |
| 4 | RSS after the targets were added | 438,960-440,384 | 366,880-370,128 |
| 4 | peak RSS during the refreshes | 502,880-507,408 | 424,128-426,688 |
| 4 | three full refreshes (ms) | 3,331-5,606 | 894-1,483 |

The RSS after setup, before any target, was 302,304-302,960 KiB in every run, so the first target cost about 40 MiB before and about 24 MiB after (it also pays for the query's one-time structures), and each further target about 31 MiB before and about 14 MiB after. The initial-snapshot measurement of the previous section, three runs each: process peak RSS 353.3-353.6 MB before and 335.4-335.6 MB after; time to the first document 114-156 ms before and 87-145 ms after (overlapping under load); no change is claimed for the final boundary.

What is still proportional to the result: the target's map (about 140 bytes per document, one per target), the handles of a snapshot being delivered, and the payloads of documents replaced before they are delivered. A bound independent of the result size still needs the history-pinning decision above.

