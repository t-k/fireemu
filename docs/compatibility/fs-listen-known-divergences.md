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
