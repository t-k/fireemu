# Listen known-divergence comparison

A registered frame-summary quote bounds the declared local sequence; it is not evidence that document values, target membership, errors, or invariants match production. `compareRecordings` now requires the complete retained canonical row to agree after a limited reconnect replay normalization. The optional recorded production quote must also match.

The supported exception is an ADD acknowledgement and its token-bearing boundary, a run of document changes/deletes/removes with optional token-bearing snapshot boundaries, then CURRENT and its final token-bearing boundary. Only the boundaries inside that document replay are removed. Complete document objects are compared in that replay segment; ordering uses kind and document name and preserves order for repeated events with the same kind and name. Initial/final boundaries, target changes, token-presence values, errors, invariants, and other canonical row content remain. A boundary with unrecognized properties is retained by rejecting the normalization. Filters are not part of this exception; their additions, removals, content changes, and relocation cannot become known divergences.

The existing registration JSON files retain their original reasons and quotes. No structural expected-local template has been fabricated from the output being judged. Only `native/existence-filter/with-expected-count` has the supported boundary/order-only proof. The following 11 other unique registrations have no complete, independently bound expected-local structure in the tracked evidence:

| Register | Rows | Handling |
| --- | --- | --- |
| strict and emulator | `native/resume-token/current` | The additional filter is outside the supported exception; a differing finished row is MISMATCH. |
| L1b strict | `native/resume-grid-tc/k1-repeat`, `native/resume-grid-tc/k1-expected`, `native/resume-grid-gc/k0` | Replay/diff or filter differences fail closed as MISMATCH. The tracked L1b fixture records answer summaries, not complete expected-local rows. |
| emulator | `native/resume-token/older`, `native/resume-token/other-query`, `native/resume-token-expired/expired` | Filter-removal differences fail closed as MISMATCH. |
| emulator | `native/existence-filter/without-expected-count` | Added replay documents are not boundary differences; a differing finished row is MISMATCH. |
| emulator | `native/resume-token/invalid`, `native/target-protocol/id-after-assigned` | These entries already lacked an eligible quoted local sequence; differing finished rows remain MISMATCH. |
| emulator | `native/target-protocol/missing-index` | This entry already lacked an eligible quoted local sequence. An unfinished local wait remains INDETERMINATE, never a successful known divergence. |

MATCH, NONDETERMINISTIC, and missing-row handling retain their existing contracts. The historical `coversLocalTimeout: true` flag no longer promotes any unfinished local row to KNOWN_DIVERGENCE: even a matching boundary-only exception remains INDETERMINATE until the stream observation is complete. Completed boundary-only observations retain their positive regression. This change tightens acceptance of declared differences; it does not assert that production behavior has changed or that an unsupported local answer conforms to production.

## Coverage obligations

| Obligation | Verification |
| --- | --- |
| Preserve the approved boundary/order-only positive | Actual `compareRecordings` fixture-backed regression and CLI success case. |
| Reject changed document fields, target membership, concrete removed IDs, invariant violations, and stream termination errors | Separate negative regressions, including summary-quote equality checks. |
| Preserve arbitrary equal document values and target IDs while rejecting one-sided mutations | Seeded property with 64 samples and four mutations per sample. |
| Retain acknowledgement/final boundary content and reject unrecognized replay boundary metadata | Boundary near-miss regressions. |
| Reject unsupported filter removal, addition, and relocation | Actual L1 fixture-backed filter-removal tests plus synthetic registration near misses. |
| Reject unsupported non-boundary quotes and program errors; bind any recorded production quote | Dedicated negative regressions; original timeout and missing-row tests remain. |
| Demonstrate semantic sensitivity of the changed functions | Scoped hand mutations of the structural proof and each retained-content guard, with baseline and unchanged control. |

## Node SDK111 reconnect observation (2026-10-11)

Two independent production recordings of `FS-LISTEN-SDK-111` (deletion and query-membership loss while offline, followed by reconnect) completed with Firebase 12.18.0 on Node 24.14.0. In both recordings, the complete retained `sdk/111` row equals the recorded strict and emulator rows. The comparison preserves all four ordered callbacks, the baseline marker, aggregate observations, snapshot cache/pending-write metadata, ordered document changes and their indexes, errors, failures, invariants, timeout status and the recorded stream end marker.

Using the case's logical document names, the callbacks retain `alpha,beta,gamma` from cache, the same documents from the server, the same documents from cache after the offline boundary, then server-backed `alpha`. The final callback removes `beta` and then `gamma`, each at old index 1 and new index −1. All four callbacks have `hasPendingWrites=false`; errors, failures and invariant violations are empty, and the row is not timed out. This is an observation of the retained Node SDK callback and aggregate axes.

| Evidence identity | Commit or SHA-256 |
| --- | --- |
| Capture source commit | `7ffcae7cdfdf4cafe2c026e29727c51006f59925` |
| Case implementation (`conformance/src/fs-listen/sdk-cases.mjs`) SHA-256 | `7bb673d61871e1ec577d13b524ec80357bcbf4c5b46525368ab60312285ebb4c` |
| Comparison source commit | `35673873bad106edf6d905071f3f16ed5f7ccefc` |
| Comparator (`conformance/src/fs-listen/compare.mjs`) SHA-256 | `16397beb41eba78e9d0375526d71a5829f07a8eaebc250837a6811bcdd78f0f9` |
| Local binary build source commit | `b592f27c18f7383bd40d564435aa7823963896c9` |
| Local `fireemu` binary SHA-256 | `0faa25cf7b259ec1488da7b92f72d70f6435aa1a5edaa276bbe23b95af74afe5` |
| Production recording R1 SHA-256 | `59ba6d778bab363b26a1bc80c11121eac555b06809a7214ad152217672af385e` |
| Production recording R2 SHA-256 | `084a983df13281f3f3e3c32c8949c7bdd838fa1f5ee9d132a06876de4964516e` |
| Strict local recording SHA-256 | `5d87ad215ce92cb71054935f3a7be1e57ad9ccb8e57ba9bff7351e4a15ce1a56` |
| Emulator local recording SHA-256 | `05ac849379184b56af97169953035d5b6ec72a5f073a2fb385421c134e76a074` |

The recordings do not establish document field values, per-document metadata, a separate per-step transcript, browser transport or application UI behavior, other SDK versions, online-reconnect variants, tenant behavior, Android/Apple behavior or raw-token behavior. They do not qualify another native registration, including `native/resume-token/current`, or replace historical artifact/build mappings. The historical native reasons and production/local quotes remain unchanged: this scoped SDK observation accompanies `native/existence-filter/with-expected-count` and does not convert its native wire differences to MATCH. The other 11 registrations and the existing timeout, filter, document-field and target-content guards retain the treatment above.
