# Broad local inspection: Identity Platform and Firestore

The first broad milestone executed three functional families for each service against the frozen strict artifact at `a68fab129c206fba08692e97038377ae1d1a50b2`. No Firebase production operation was performed. Lifetime revision 3 remains a prepared, offline-validated, production-unobserved deep dive; GAP-AUTH-007 and AUTH-U03 remain open and do not block this inspection.

[Machine-readable catalog](../../spec/compatibility/broad-catalog.json), [execution manifest and all normalized case results](../../spec/compatibility/broad-runs/a68fab12.json), [cause-level triage and minimal reproduction](../../spec/compatibility/broad-runs/triage.json), [runner/coverage documentation](../../tools/compat-broad/README.md), and [proposed production envelope](broad-production-envelope.md) are separate from the pinned historical lifetime receipts and their approvals.

| Executed family | Current artifact checks | Historical production reference matches | New local invariant passes | Indeterminate |
| --- | --- | ---: | ---: | ---: |
| Auth accounts | Create/lookup/update/delete, five/six-character password boundary, rejected-create absence and deletion readback | 3 | 8 | 0 |
| Auth credentials | Password sign-in/refusals, password change, old/new credential behavior and refresh identity | 13 | 4 | 0 |
| Auth authorization | Invalid credentials plus admin/self/other-user/unauthenticated update and unchanged ownership/state after refusal | 6 | 7 | 1 |
| Firestore writes | Masks/preconditions, atomic commit, batchWrite, empty commit, transforms and rejection poststate | 39 | 4 | 20 |
| Firestore queries | Inclusive/exclusive/prefix cursors, zero/negative limits and unchanged document state | 15 | 3 | 0 |
| Firestore transactions | Begin/read/commit/rollback/conflict and poststate | 30 | 0 | 2 |
| Total | Six executed functional families | 106 | 26 | 23 |

There were zero remaining comparable mismatches, zero failed new invariants and zero missing selected steps. Skipped/unselected capability areas remain visible in the catalog; this does not mean every API method passed. The 169 known pinned REST/protobuf methods are a source inventory denominator, not full field/behavior coverage. The initial selection excludes tenant/provider integration, MFA deep dives, OOB delivery, blocking functions, management APIs, broader filter/aggregation/index permutations, user Rules, SDK, gRPC/WebChannel Listen/reconnect and Enterprise/Pipeline/full-text/MongoDB execution. Their next units and external dependencies are recorded explicitly; implementation status remains unknown unless existing capability evidence establishes it.

## Cause-level triage

The first run at `9f94d06d9c52ec7f3d8add5fb5ee0716aea25f5c` had 105 matches, one mismatch, 23 indeterminate rows and 26 local invariant passes. The mismatch was the prefix-cursor query ordered by `g,n`, refused with a missing-index error. The strict harness had omitted the composite index configuration present during the historical production observation.

The minimized reproduction uses one seeded document and one query. On the same final binary, omitting the index file returns 400 `FAILED_PRECONDITION`; loading the exact historical index bytes returns 200 with the document. The pinned index SHA256 is `8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c`. No cursor/runtime patch or expected-response rewrite was justified. The harness was corrected and all related selected cases were rerun. This is one configuration cause, not a newly discovered independent Firestore implementation gap.

The 23 indeterminate rows comprise 20 current transform steps whose whole operation sequence differs from the recorded corpus, two transaction write requests that did not produce usable responses, and one unknown Auth method with a non-JSON local response. They are not counted as matches, distinct bugs or production failures. The unchanged transaction rows are exploratory observations; incomplete contention history is not a universal ordering oracle.

## Evidence and execution limits

The historical Auth corpus is bound to `2ec9758a99952d9db976ccc05bd92fa12a81ec8f`; the Firestore corpus/index reference is bound to `2526c61eda5fc53ac91250307786127ae3c601be`. The runner reconstructed and checked the original corpus digests and session/normalizer bytes, then required typed whole-program equality before joining case results. The transform ID reuse was therefore excluded. Historical results were never promoted into current execution evidence.

Historical normalization removes some identifiers and time/expiry fields. Error comparisons retain status and machine code; raw message differences remain available. Ownership is checked explicitly by the new local scenarios, not inferred from opaque historical placeholders. Production OAuth/local-owner Firestore comparisons concern privileged Standard Native REST semantics only; they do not establish user Rules, other editions, SDK or stream compatibility. These results are exploratory scoped references, not a formal whole-service compatibility approval.

The broad executions used the same runtime source inputs, but separately built artifacts; the minimal index/no-index experiment independently used exactly one binary. The final manifest records the exact artifact SHA256, execution source files, runtime inputs, strict configuration, historical index bytes, selected programs and seed 20260912. Owned process exit and Auth/Firestore/control listener closure were confirmed. The actual execution commit remains explicit even when later documentation-only commits are present.

## Validation performed

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad tools/auth-pending-lifetime tools/auth-pending-lifetime-boundary tools/auth-pending-lifetime-window -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --check-catalog
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/broad.py --run --output /absolute/private/new-broad-run
```

The combined pytest command passed 135 tests at the frozen execution milestone, including 19 broad safety tests. The guard's finite model covered 48 host/protocol/credential/request/deadline combinations. Eight selected source mutants were detected after an unchanged copied baseline passed 19 tests. Real local HTTP redirect/reset tests and real Node/sleep process tests confirmed cleanup paths; all test processes were stopped. Ruff, ty, OxLint/OxFmt and actionlint passed. The owned command built the current artifact successfully. A workspace-wide Rust nextest run was not performed for this tooling-only milestone; no runtime Rust implementation was changed.

All four existing lifetime production/comparison publishers passed `--check` with unchanged subjects. Compatibility CI now runs the broad offline suite and catalog/source binding check alongside the existing lifetime suites and publishers. The Node dependency lock was installed with `pnpm -C conformance install --frozen-lockfile`; no dependency versions changed.

Security/comparator review at `a68fab129c206fba08692e97038377ae1d1a50b2`: Must Fix: none. Should Fix: none. Earlier findings were repaired: registration/cleanup errors cannot skip owned-parent termination, Node registration is protected from its first write, request joins preserve boolean/number distinctions, and seeded readback checks exact document identity. The AI review approves the local implementation only; the production envelope remains an unapproved proposal and grants no revision 3 execution permission.
