# Parallel exploration checkpoint

The fixed test source is `6ae42fb170857b324e7d4b271011e5ef505d9a05`. Four bounded `gpt-5.6-luna` exploration lanes covered claims, tenant refresh, transaction/BatchWrite contention, and Enterprise/Listen assets. At most three explorers ran concurrently because the session exposes four slots including the coordinator. Two workers used separate worktrees and non-overlapping test files. The coordinator alone integrated changes and ran Cargo. No production requests or credential checks were made.

## Additional coverage

| Existing catalog family | Executed additional condition | Remaining question |
| --- | --- | --- |
| Auth tenants | Cross-tenant refresh in both directions preserves both populated namespace snapshots; subsequent rightful refresh succeeds with the correct tenant claim | This fixture uses stateless refresh. Strict-profile revocation and production error precedence remain unobserved |
| Auth custom token | Issued session claims do not become persistent Admin `customAttributes`; the lookup must return exactly the intended user | Production issuer/claim combinations and persistent-claim merge behavior need separate evidence |
| Firestore writes/transactions | A first or middle locked BatchWrite item fails independently, successful other writes retain their versions, the holder can commit and release its lock | This is gRPC local coverage. REST equivalence and production mixed-contention response forms remain unobserved |

The [machine-readable record](../../spec/compatibility/broad-runs/6ae42fb1-parallel-local.json) contains the actual test binary hashes and result classes. Hashes were collected through Cargo/nextest after execution, not recorded by a prelaunch artifact collector. No new server artifact or production parity result is claimed. Existing193-reference comparisons, first46, second45, and their historical failures/contracts remain unchanged. There is no new established runtime gap or runtime modification.

The related adapter suite passed535 tests with one existing skipped test; nextest reported19.818 seconds and Cargo reported1.27 seconds for the final compile. Clippy passed. An initial compilation error and missing Auth project setup were corrected. Independent review also required positive account-count/UID assertions to prevent vacuous lookup success; final review reports no Must Fix or Should Fix findings. Mutation, full-workspace testing and the46/45 replays were not rerun in this test-only checkpoint. No mutation build was started or adopted.

## Shared execution frame: pending implementation

The two-window, globally4-request/second frame remains an unapproved proposal, not an executable shared admission. Existing per-adapter budgets do not yet coordinate across processes. Do not launch parallel production collectors on the strength of this checkpoint.

The next implementation must attach a shared admission gate to existing adapter request reservation, binding each closed manifest, collector, namespace and operation allowance. Allocate observation and recovery request/time/cost capacity globally before claiming a scenario. Recovery is a tagged subset of total requests, not an additional total. Count operation-specific Auth creations/deletions and reserve owned resources; a global rate alone is insufficient. Hold resource ownership after incomplete recovery, allow recovery while observation is stopped, and distinguish scenario-local from environment-wide stop. Shared-setting experiments and queries that escape namespace isolation require exclusive admission. Keep the first integration offline/local-only until its safety boundary is reviewed.

Official [Auth limits](https://firebase.google.com/docs/auth/limits) list100 new accounts/hour/IP,10 account deletions/second and10 account configuration updates/second. The effective current project quota and shared-IP headroom were not inspected. Neither these public reference values nor a4-request/second scheduler grant execution permission. Owner, period, nonce, current environment acceptance and additional-cost approval remain unset. The existing cost/resource manifests must supply full operation quantities, including setup, authentication, metadata and recovery, before a combined proposal is executable.

Enterprise remains in the queue: function options are currently discarded during wire conversion and execution remains unsupported. This is an implementation boundary, not evidence for a speculative production error fix. Establish documented expression signatures/options before implementing a bounded unit. SDK identity switching and browser/WebChannel coverage remain separate from existing local gRPC Listen checks.

## Timing and resumption

Only final Cargo compile and nextest durations were measured in this checkpoint. Preparation, analysis, corrections and review timings were not instrumented and remain unknown; agent estimates are not substituted. Production communication and approval waiting were zero. Add monotonic phase timestamps at dispatch/integration boundaries before using elapsed times to choose further concurrency.

Resume with the shared local admission gate and real multiprocess contention tests for global capacity, recovery reservations, per-operation rate, disjoint ownership and incomplete cleanup. Then replay two closed local manifests through existing adapters. This checkpoint does not satisfy that unfinished execution-management requirement. All additional evidence is local, and no owner decision is needed to continue that work.
