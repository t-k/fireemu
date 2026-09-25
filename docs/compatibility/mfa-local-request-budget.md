# MFA local request accounting

This is a local runner contract, not production admission, Google pricing, or a
restart cleanup capability. The frozen campaign manifest and historical receipts
are unchanged. The current `Instance` enforces the request cap before invoking
its fixed HTTP worker; direct callers of the generic worker are not governed by
an `Instance` they do not use.

## Allowance

The existing whole-run limit is **400** attempted requests. Two calls for each of
the existing maximum **14** owned accounts are reserved within that limit:

| Phase | Maximum | Included operations |
| --- | ---: | --- |
| Observation, setup and inspection | 372 | Signup, Auth operations, emulator inspection, clock control |
| Recovery | 28 | One delete followed by at most one lookup for each confirmed UID |
| Whole run | 400 | Sum of both phases, never an additional allowance |

If fewer accounts were acknowledged, the reserved tail remains at most two calls
per acknowledged UID. Unused recovery slots cannot fund more observation calls.
A timeout, refusal, malformed response, worker failure or exception stays charged.
An input rejected before admission does not consume a worker attempt; an admitted
attempt can fail before bytes reach the socket. Counts are therefore conservative
worker dispatch attempts, not packets, Google-billed requests or successful writes.

Recovery entry is one-way and idempotent for the same UID set. Re-entry does not
reset counters or per-UID slots. Recovery bodies are copied before admission so a caller cannot retarget the
validated UID by changing a dictionary or list during the send.
A different set, an unrelated endpoint, a query
alias, an extended body, a non-owner token, a duplicate delete or a lookup before
the delete is refused. One active call per instance is allowed; phase transitions
and close cannot race an admitted in-process call. Failed deletes are not retried.
The existing recovery loop skips their lookup and retains that UID as unrecovered.

The scope comes from this run's already-confirmed ownership records, not a
checkpoint loaded from another run. The budget only limits requests: it does not
establish that the supplied UID is owned. Existing typed signup and cleanup
checks still establish that authority. Unknown signup outcomes remain unknown.

## Integration and evidence

`run_sequence` binds a fresh plan once, before any service request. A used or
closed instance cannot be rebound. It enters recovery using its confirmed UID
set even when observation raises. The terminal request count comes from the
transport meter, not an inferred one-call-per-case count. The final private
recovery record retains a `requestBudget` snapshot even when observation fails;
normal public reports carry the same summary. The summary contains no UID/token.

Current parent execution requires the summary and checks the plan digest, strict
integer counters, phase, limits and total. The saved comparator checks summaries
when explicitly present, preserving historical schemas without claiming that
older receipts were made by this runner. The new module is source-bound by MFA
provenance. Old hashes are not refreshed to masquerade as new native execution.

An attempted observation past the reserved boundary marks observation incomplete,
but does not prevent authorized cleanup. Resource cleanup can succeed while
observation remains failed. A counter summary is a consistency check, not a
signature, current-resource assertion or independent producer attestation.

## Validation and remaining boundaries

The test suite exercises actual `Instance`, `RequestBudget`, persistence and
parent/comparator code with injected service responses; one test uses the real
local TCP and fixed-worker cleanup path. Existing MFA test doubles now reuse the
real meter instead of manually incrementing a mutable counter. They still do not
execute the full native Firebase implementation.

This change does not add a global cross-process ledger, new retries, deadline
extensions, pricing enforcement, restart authority, instance identity attestation
or automatic orphan deletion. Existing per-request/parent time bounds remain.
The native artifact, fixed SDK and current-source local shadow still need to run.
