# Listen full-refresh delivery and snapshot retention

The full-refresh implementation selects immutable document handles before sending responses. It encodes a document only after reserving an outbound channel slot. This bounds queued encoded responses, but the selected immutable handles and the payloads they keep alive remain proportional to the result size. There is no new paging implementation in this change.

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

Adding a history pin would require an explicit decision about history limits, write admission and restore. It could also retain the entire old result while a receiver is stalled. Holding a read lock across sends would block writers. Neither is implemented here, and this report makes no claim of bounded snapshot payload memory or a performance improvement.

## Existing semantic checks

The adapter's stream tests include `deferred_snapshot_rows_and_boundaries_survive_writes_deletes_and_restore`, `deferred_stream_keeps_snapshot_rows_before_current_during_writes`, and `slow_receiver_bounds_encoding_and_releases_snapshot_handles_on_drop`. They cover selected content and boundaries across changes, row ordering during writes, encoding backpressure, and cancellation cleanup. The measurement test complements these checks; it does not establish new production behavior.

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
