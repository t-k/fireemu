# FS-DATA-WRITE: non-production acceptance checkpoint

This checkpoint prioritizes FS-DATA-WRITE without changing its denominator.
Production observation, live credential/configuration access and approval
consumption are excluded from this work. Local implementation, native regression,
saved-reference replay, final artifact binding and independent review are **not**
reclassified as production work.

## Current source, not historical acceptance

The central condition ledger includes older unsupported labels for request,
field-path, field-value and indexed-field-value limits. The current catalog and
runtime contain implementations of all four. This is a source finding, not proof
that the final artifact passes their boundaries. Historical evidence and its
hashes are unchanged. The existing owner exclusions of managed infrastructure
are not widened to hide data-plane limits.

| Area | Current work | Remaining non-production acceptance |
|---|---|---|
| Document/reference size | Rust namespace parsing repair retained. Python limit compiler now excludes project/database namespaces even when named `documents`; exact and over-limit inputs are checked independently. | Compile and execute the five retained Rust regression tests and final native collector runs. |
| Document bytes and nesting | Existing finite collector/precondition/cleanup tests retained. Normal fixed-namespace compiled plan is byte-identical to the previous compiler. | New native artifact shadow; compare against immutable saved references with fresh binding. |
| Collection/document IDs, depth and name | Added three-point inputs and PATCH/Commit/BatchWrite native test wiring. | Native compilation and execution, including rejection-state verification. |
| Field names, canonical paths, values | Three-point scalar and aggregate cases prepared; index effects explicitly disabled. | Native handler, gRPC/Write and SDK lanes. The new handler target has not run. |
| Indexed-value truncation | Inputs distinguish capped index charging from unchanged stored data. | Actual native readback, ordering/filter implications in the appropriate query lane. |
| Index count, entry bytes and sum | Three separate explicit composite configurations isolate limits; distinct members and exact arithmetic checked in Python. | Native execution with declared index configuration, final artifact evidence. |
| API request bytes | Existing strict/emulator REST, gRPC and Write-stream tests retained; no limit increase. | Execute against final binary and create a fresh request-byte shadow. Old local artifact source mismatch remains blocked. |
| Commit/BatchWrite, masks, preconditions, transforms | Existing core/adapter and O8 acquisition modules retained. New target checks siblings and post-state at boundary rejection. | Compile/run native core and adapter suites, Write-stream/SDK equivalents and reviewed final CLI-to-collector path. |
| Returned values/errors and post-state | Existing typed collection and comparison safeguards retained. | New artifact observations, preserved diagnostic mismatches and saved-reference replay. |
| Process/resource recovery | No safety gate or transport deadline relaxed. Python O8 injected-transport integration is distinct from real artifact execution. | Real runner lifecycle proof and complete cleanup/recovery evidence on the final package. |
| Final evidence | Test receipts stay outside the source tree and bind source/tree identity. | Historical Git/private inputs where required, final artifact/observer/collector/comparator/configuration binding and independent correctness/security review. |

## Finite new corpus

`tools/compat-broad/fs-data-write-local` compiles 42 local-only inputs (14 families
by three points). The native target declares 42 tests, each with three points
across PATCH, Commit and BatchWrite: 126 **intended**, not executed, scenarios.
Python input validation is not a substitute for the Rust tests. Request bytes,
document bytes, nesting and transforms remain linked to existing separate lanes.
No case is admitted to a production runner by adding this compiler.

## Finish criteria

1. Build the final source with its pinned toolchain, format/lint it and run native
   core/adapter data-write regressions, the new boundary target, relevant streaming
   and SDK paths. Keep skips and dependency failures visible.
2. Execute fresh owned local artifact shadows for document limits, Commit and
   request bytes. Bind exact source, binary, compiler, collector, comparator and
   index configuration. Do not rewrite hashes of old shadows to simulate reruns.
3. Replay usable immutable saved production references against the new local
   artifact without new production requests. Retain mismatches and indeterminate
   rows, and resolve implementation defects where evidence supports a repair.
4. Complete independent correctness/security review and condition-level acceptance.

**FS-DATA-WRITE is not yet non-production-complete.** Native execution and final
artifact/replay/review remain blocked in the authoring environment. Nor are the
other 13 parent groups newly accepted by this focused work.

## Typed local-control and saved-receipt integrity (v17)

The finite document-size collector, local-shadow validator and interruption
rehearsal now use the existing shared Gate's typed absence/rejection contract.
A top-level success document mixed with an error cannot pass a local control.
Control documents require exact typed fields and a valid UTC version, and row
indices, Gate counters, skip flags, absence flags and rehearsal status retain
their JSON types. Cleanup DeleteDocument success is the empty response object,
not status 200 with an arbitrary/error body. Invalid response versions are not
turned into conditional-delete query parameters.

This closes acceptance inconsistencies outside the already-protected Gate; it
does not add transport, retry, budget or deletion authority. The collector still
leaves Gate failures as infrastructure failures. Complete acquisition with an
unexpectedly accepted negative boundary remains eligible for semantic comparison
when its exact acknowledged resources are recovered; cleanup validation does not
require that all observation semantics match local expectations. A rehearsal may
pass its recovery check without declaring campaign completion. Malformed saved
receipt structures return a rejected validation, rather than escaping as an
uncaught shape exception.

`test_shadow_integrity.py` supplies finite synthetic records and exercises the
real collector/Gate. It is not native, SDK or production evidence. None of the
existing immutable shadow receipts or their expected source/artifact hashes are
rewritten. Native execution, new artifact shadows, saved-reference replay and
independent review remain required by the finish criteria above.
