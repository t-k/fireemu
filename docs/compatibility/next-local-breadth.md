# Local breadth after the second45 repairs

This milestone adds local tenant, transaction/BatchWrite and Listen conditions instead of further refining the second45 batch. No Cloud/Firebase reads, credential checks or production writes were performed. Rust runtime sources and comparison semantics were not changed. The original32/13, repaired45/45, first46 and historical artifacts/contracts remain unchanged.

## Additional conditions

| Area | Newly exercised condition | Evidence class and remaining boundary |
| --- | --- | --- |
| Auth tenant boundary | Each tenant's token is refused against the other's namespace; full snapshots of both namespaces remain equal; valid own-token lookups succeed | Local Auth handler invariant; custom-token claims and production tenant configuration are separate |
| Firestore BatchWrite | First or middle decode/execution failure leaves successful suffix writes present; every status/result aligns with the corresponding document/version | Local gRPC invariant, four combinations; the historical duplicate-target rejection is not evidence for this partial-success case |
| Firestore BatchWrite REST | A malformed document name and an exists-precondition failure occupy their response slots while valid prefix/suffix writes and pre-existing documents retain the expected state | Local REST handler invariant, two failure positions; production REST response and post-state remain unobserved |
| Firestore transaction Commit | A late Verify or delete precondition failure preserves existing and guard documents including versions, publishes no staged create; the corresponding valid commit succeeds after rollback | Local gRPC atomicity; no claim about production failed-transaction reuse or multiple-error priority |
| Listen and Rules | Denied resume produces no documents; permission recovery does not resurrect the removed target; explicit re-add observes the latest document | Local gRPC/Rules behavior; SDK identity switch, browser/WebChannel and production reconnect are unobserved |
| Enterprise | Existing stage/edition validation and text-index validation executed | Validation only; Pipeline execution and expression semantics remain unimplemented/unobserved |

The feature catalog now separates recorded second45 Auth conditions from remaining values, principals and routes, and records the new local invariants separately from production parity. `currentStatus` does not inherit a pass from these historical records.

No new runtime gap was established by these cases, and no speculative runtime fix was made. Enterprise is divided into stage/wire validation, function-option preservation and signature checking, read-only Pipeline execution, and separate text/vector/write/MongoDB work. Standard evidence cannot establish any of those edition-specific execution semantics.

## Verification and artifact

The fixed artifact/execution commit is `24d07bc230a833453e206c0a0ddb32a22d4d9faa`; SHA256 is `df49082de278f72cc133a98d25d1bdeae9ce680d701efb6c5e9c95f3017c4882`. A verified private copy was retained. The [machine-readable summary](../../spec/compatibility/broad-runs/24d07bc2-next-local-breadth.json) records its source/configuration/input identity and result categories.

- Four new targeted Rust tests passed. Their table-driven scenarios include both failure positions/types and nearby successful controls.
- Related HTTP/gRPC regression:533 passed, zero failed, one preexisting large release-mode stream acceptance test skipped. The full workspace was not rerun. Clippy for both adapters passed after adding narrow test-function length allowances.
- Enterprise core validation:2 passed; existing gRPC Pipeline validation:1 passed. These are executions of existing coverage, not newly implemented Enterprise functionality.
- Broad/guard/owned Python checks:244 passed,2 initially skipped for lack of an explicit artifact. The owned-runner suite was then run with the verified artifact:20 passed, zero skipped. Final mutation-guard tests:18 passed after adding inherited target/build environment coverage. Catalog checks:21 passed. Ruff/ty passed for the changed guard/test modules.
- The fixed broad artifact replay returned193 matches,23 indeterminate and26 local checks. These are existing coverage re-executed on this artifact, not new coverage or219 production matches. The historical23 buckets remain20 changed-transform sequences,2 unavailable transaction responses and1 non-JSON Auth reference; this does not undo the separately observed current transforms in first46.
- Owned supervisor/listeners stopped, including the real-artifact integration executions. No production resources were created. The two worker worktrees were integrated and removed.

Mutation admission now protects both final and intermediate outputs, including inherited Cargo environment and configured directories. Independent review found two initial bypasses (intermediate output and explicit binary adoption); both received failing negative tests, fixes and an approved follow-up review. The later environment-override advice is covered by real Cargo subprocess tests. See [mutation build isolation](mutation-build-isolation.md). No mutation artifact was used for this milestone's normal artifact.

Representative commands were `cargo nextest run -p fireemu-adapter-http -p fireemu-adapter-grpc --profile pr`, the two Enterprise filters recorded in the summary, `uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad tools/compat-inventory/test_mutation_cargo.py tools/compat-inventory/test_owned_runner.py -q`, and `tools/compat-broad/broad.py --run --output <private-output>` under that same locked environment. The later commit adds only environment tests/catalog records; it does not replace the fixed artifact identity.

## Next observation questions and local queue

The next small production question is BatchWrite per-item response shape and side effects when a distinct middle write fails decoding or an exists precondition. The old duplicate-target fixture cannot answer it. Equivalent REST local cases now run through the real handler and cover both failure positions, but this is not production evidence. The existing REST production adapter can use these cases as the local shadow prerequisite; its proposed data work is two variants, each one three-write batch, three readbacks, up to three recovery requests for each of the three journaled targets, allowing an ownership read, deletion and absence confirmation (up to26 data requests overall: two times1+3+9). Authentication/metadata/recovery reservations, closed manifest, current configuration and cost validation remain to be bound. This is a question package, not an executable admission or authorization; owner, window, nonce and budget approval remain unset.

Tenant configuration, custom-token issuer/claims, Rules changes and production Listen require different credentials or setup and stay outside that ordinary data-only proposal. They do not block further local work. Next local units are custom-token claim isolation, BatchWrite contention with an active transaction, SDK identity switching, and Enterprise expression-option/signature validation backed by explicit documented signatures. Revision3, GAP-AUTH-007 and AUTH-U03 remain independent.
