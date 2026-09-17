# Shared production reservations

This internal one-host library extends the existing Gate file protocol with cross-campaign admission. It does not approve production permission, run a scheduler, acquire credentials, or execute a campaign. O7 must validate the owner envelope and exact manifest, then use one canonical shared directory for every worker. A separate directory per campaign would defeat shared admission and is not an allowed production configuration.

`Ledger.create(path)` initializes a new private directory once. `Ledger(path)` requires existing state and never creates a fallback. Tickets bind the canonical ledger path and identity, the campaign claim digest, and the envelope digest. A copied ledger at another path cannot consume the original ticket. State remains bounded to 10,000 reservations and 16 MiB; reaching either local bookkeeping limit refuses new admission.

## Admission and accounting

`reserve(envelope, claim, gate_plan)` atomically checks the permission window, envelope scope, exact Gate plan, fresh nonce/Gate path, active lock conflicts, concurrency, and every budget dimension before persisting a reservation. Budget dimensions are integer upper bounds for requests, accounts, resources, and micro-USD. The full campaign allocation stays allocated permanently, including unused capacity. Release never refunds it. This conservative first version avoids treating a failed or ambiguous attempt as unused capacity; allocations are upper bounds, not measured cloud charges.

The existing campaign Gate remains responsible for per-attempt counting, deadlines, cost, ownership proofs and conditional cleanup. There is no second per-request accounting protocol. The shared ledger checks that the declared campaign allocation covers the Gate's observation/recovery/management request ceiling, cost ceiling, resource count, and duration. Owned Firestore document resources must be covered by a declared WRITE or EXCLUSIVE scope. O7 must separately bind account counts and every configuration/metadata dependency to the exact manifest; resource coverage alone does not establish those dependencies. A production Gate's permission digest must match the envelope permission digest. One permission digest cannot be reused with a different envelope.

Lock keys are project-qualified, segment-preserving paths, for example `project/fireemu-35fe6/firestore/(default)/documents/oracle/<nonce>/limits-02/*`. Only a terminal `/*` is accepted. Empty segments, dot segments, percent encodings and interior wildcards are rejected. Parent and child scopes overlap; siblings do not. Overlapping READ locks are compatible; any overlapping WRITE or EXCLUSIVE lock conflicts. Conflicts apply across envelopes, not only within one permission.

## Lifetime and cleanup

A reservation remains held after its deadline or worker exit. Neither a PID sweep nor expiry releases ownership. `validate(ticket)` refuses new work after the deadline or while the reservation is closing/released. Real time is sampled inside the acquired ledger lock, so waiting for admission cannot preserve an expired time check. No plaintext credential is stored in this ledger.

`finish(ticket)` first changes the lease to closing, then releases the ledger lock before reading the registered Gate. Dispatch must check the lease before transport. This lock order prevents a Gate-to-ledger/ledger-to-Gate deadlock. Release requires the exact frozen Gate plan, no in-flight work, every job marked complete, all assigned resources confirmed absent, and counters within the original allocation. An incomplete Gate restores the held state for bounded recovery; interruption during finalization retains the closing state and requires explicit recovery. Successful finalization releases locks and concurrency only, retaining the claim, nonce, allocation, and final Gate digest.

This cleanup check does not validate the final production comparison, owner approval provenance, artifact build, metadata/configuration equivalence, or receipt completeness. Those remain the outer runner's responsibility. Historical approvals and observation receipts are not rewritten by ledger updates.

## Limits integration

`fs-write-limits/production_bridge.py` provides `ReservedCoordinator` and `bind_reserved_wire`. The Coordinator freezes the ledger identity and ticket as well as verifying the exact registered Gate; replacement of those bindings is refused; management attempts validate the shared lease after the existing rate wait and durable attempt accounting. Data sends validate it inside the Gate callback after its rate wait. The reservation implementation is included in the collector source digest. The production entrypoint must use this reserved variant, the fixed wire transport, and a canonical shared ledger; the lower-level unreserved bridge remains an internal component and test surface, not production admission.

Focused tests use actual files, spawned processes, Gate accounting and synthetic bounded transport responses. They cover atomic contention, ancestor conflicts, permission-envelope reuse, nonce reuse, expiry, worker interruption, complete cleanup, closing-state refusal and lock ordering. No test in this directory acquires credentials or sends a production request.
