# Firestore Standard Write stream: local coverage

This artifact records finite local coverage for `FS-WRITE` at the Standard/Native gRPC adapter boundary. It does not establish production compatibility or official emulator parity.

The covered conditions are:

- the first request names the database and acts as a no-write handshake;
- dependent writes execute in request order; responses and write results preserve request order,
  with distinguishable pipelined batches, fresh stream tokens and commit/update times;
- server timestamp transforms are materialized in the committed document;
- an atomic request refused by an exists precondition publishes no earlier write in that request;
- a refused stream can be closed and a new stream can commit against the same database;
- a graceful client half-close ends the stream without a mutation;
- an invalid token is refused and does not publish its request (existing regression coverage);
- tokens are bound to the exact stream instance, with mismatched stream IDs, cross-stream replay,
  stale acknowledgement and future tokens refused; same-token pipelining remains supported.
- a write stream targeting a document read by an active read-write transaction is refused with
  `ABORTED` without publishing any item in its multi-write request; after rollback, a fresh stream
  can write the document.

The local precedence observed for the conflicting `exists=false` update against an existing document is `ALREADY_EXISTS`. Production precedence is an explicit coverage debt because no saved production observation is bound to this case. Stream resumption across a closed stream is unsupported; reconnects start a new stream.

Evidence is provided by `crates/fireemu-adapter-grpc/tests/streams.rs`:

- `write_stream_handshake_then_sequential_commits`;
- `write_stream_accepts_pipelined_acknowledgements_and_once_targets_are_removed`;
- `write_stream_preserves_order_preconditions_transforms_and_post_state`;
- `write_stream_graceful_half_close_has_no_side_effect`;
- `write_stream_tokens_are_bound_to_stream_and_stream_id`;
- `write_stream_enforces_handshake_and_database_ownership`;
- `write_stream_rules_refuse_malformed_and_wrong_audience_auth`;
- `write_stream_enforces_handshake_and_database_ownership` (exact formerly accepted
  even-tail database-root case and same-project foreign database refusal).
- `write_stream_refuses_active_transaction_contention_without_mutation` (active transaction
  contention and post-rollback stream recovery).

The capability mapping is `FS-RPC-1` in `crates/fireemu/src/capabilities.json`. Active-stream acknowledgements are covered; closed-stream resumption is unsupported. The stream/transaction contention response and atomic no-mutation behavior are local observations; production error wording and ordering, REST and SDK parity remain unobserved. `FS-WRITE` is mapped to `REQ-FS-PARITY-01` in the surface inventory as finite local evidence. The generated inventory is `docs/compatibility/surfaces.md`; the broader Standard/Native feature mapping remains `FS-DATA` in `spec/compatibility/features.json`.

## Bounded Node transport preparation

The local-only transport in `tools/compat-broad/fs-write-txn/stream_node_transport.mjs` reuses the pinned SDK dependency tree and requires an explicit loopback host, port, project and owned document prefix. It sequences Write handshake and response tokens, reads terminal gRPC status, bounds frames/message sizes/deadlines, rejects namespace traversal and caller target overrides, and retains serializable error/status observations. Incomplete terminal sequences remain incomplete rather than semantic outcomes. No ADC lookup or remote production endpoint is supported.

The integrated deterministic suite passed 14 tests with one explicit live-endpoint test skipped when no endpoint is supplied. The transport owner separately ran that live suite against the retained `a7e182d93` strict artifact under the port registry: 15 tests passed, and the owned daemon/processes were stopped. Independent review approved this local transport scope after path, terminal and serialization repairs. A final follow-up closes the client on synchronous stream creation failure and validates options at the public write-validation boundary.

This completes a collector dependency only. The finite transaction-contention collector, immutable acquisition journal, cleanup/failure rehearsal, production transport/admission and stream comparison contract are still separate preparation conditions. Document-byte and nesting cases already observed by `FS-DATA-WRITE-LIMITS-02` must not be scheduled again in the stream campaign. The consumed limits permission does not authorize Write-stream observation.

## Finite contention collector checkpoint

The independently reviewed finite collector was integrated at `04bd87e88`. It uses three nonce-scoped document candidates, a fresh internal per-invocation ownership marker, typed absence preflights, exact owned post-state checks and version-conditional cleanup of attempted resources. Incomplete writes stop further observation and retain bounded recovery responsibility. A pre-existing same-nonce resource is not treated as owned by this invocation.

The integrated suite passed 26 tests with two explicit live-endpoint tests skipped. The original owner-reported local run used artifact `9549069cc45c5ccb24b78d9312df3104399681077614814f9f9f19fac5468ab4`, but its binary and logs were mistakenly retained inside the removed worktree. That run is no longer counted as reproducible retained evidence.

A replacement run of collector source `6ded4fc5e75bc0c741ca789b2a322af951cd9ef2` used the independently retained, manifest-bound runtime artifact from `8b33aac4ddd09e6b945cc8701a7e757a948223ac`, SHA-256 `76f855367910ad237de6ffd491091f20bcdccdb2e5eb8ee417e80b94bf6ac397`. Root-owned execution captured terminal `ABORTED`, unchanged locked state, absent suffix, successful post-rollback write/readback and typed absence for all three attempted candidates. The process exited successfully, no process using the owned artifact remained, and the artifact hash remained unchanged. The private retained receipt digest is `7b733a73ff547dfbb6d3f8e5402a81f5fa0db64aa1f0864ab8e2516c2cc8e5a0`. Config SHA-256 is `a8070d1f2d6337b3bcb59de8e65bdf7666260b40e520bcc2df4391f9297623f6`.

The daemon waits up to 15 seconds for contention; the former ten-second collector deadline expired first. A bounded thirty-second transport deadline records the actual terminal response without changing runtime behavior. This is a new local verification, not a production re-observation or an attempt to reconstruct the lost artifact.

The local preparation condition is reduced, but production transport/admission, an immutable stream comparison contract and complete failure rehearsal remain required. No production observation was made and the consumed limits permission is not reused. The CLI's bracketed IPv6 parsing improvement is deferred; this checkpoint uses the verified IPv4 loopback path.


## Reviewed transport boundary

The fixed TLS transport seam was integrated at `d8501544c` after independent review of `ce88a5fd2`. Local and fixed-endpoint execution share the unary and Write receipt logic. The internal production factory requires trusted admission, rejects invalid requests and deadline overrides before client construction, and rechecks the phase and credential deadlines after asynchronous admission. TLS credentials and the endpoint are transport-owned. No production request was made by these tests, and this component does not itself provide campaign approval or the missing stream acquisition/comparison binding.

The combined integrated Node suite passed 36 tests with two explicit live-endpoint skips at `00385a668`. The Auth harness and Explain preparation checks passed 129 tests. The preceding clean broad checkpoint `3a0608904` passed 930 tests with 10 skips after isolating the new transform modules from the existing limits compiler imports. These results are local validation, not new production observations.

## Outbound-frame and cleanup proof checkpoint

Transport receipt version 2 records immutable snapshots of outgoing logical Write messages and distinguishes attempted sends from completed `stream.write()` calls; neither count proves server acknowledgement. Explicit GAX retry suppression prevents hidden logical RPC retries. The separately reviewed unanswered-RPC fixture uses a real local gRPC server, a bounded one-second deadline and guaranteed server/client cleanup. At `00c77a700`, the combined Node suite passed 35 tests with two opt-in live tests skipped.

Collector source `0898b2246b8d28fcdf9f2149cd35ab52199b2f24` also retains the final owned read used for each conditional cleanup delete. A new actual local run used the retained `8b33aac4ddd09e6b945cc8701a7e757a948223ac` artifact and configuration hashes above. All five collector semantic checks succeeded. Cleanup proved absence for all three candidates, retaining two owned-read/delete proofs and one already-absent read. The daemon exited, no owned process remained and the artifact digest was unchanged. The new immutable private output SHA-256 is `a0f3a2e5f2a1dbe891992f20ef394369c595063334be5d90fa14d3d64803dd46`. Earlier receipts remain unchanged; missing outbound-frame proof is not retroactively fabricated.

The default local path was independently reviewed. Delegated recovery is an internal trusted-worker boundary and still requires equivalent transaction-release, ownership, conditional-delete and typed-absence proof before acquisition finalization. The stream comparator and shared Gate integration remain under review. This checkpoint is local evidence only and does not promote a parent or authorize production execution.

## Bounded terminal repair

The terminal repair at `215ae10f4` addresses early stream termination leaving ACK waiters unresolved and oversized terminal diagnostics escaping event handlers. All pending and later response waits terminate, no subsequent Write is sent after terminal signaling, and client cleanup runs exactly once. Missing ACKs with an OK status remain incomplete; actual nonzero gRPC status refusals remain observable. Numeric error codes without a status event do not manufacture terminal proof. Oversized status/error fields are omitted in favor of a bounded `message_limit` failure.

The original source failed six new controls, including waiter watchdogs and uncaught oversized-event exceptions. Independent review approved the final repair; the integrated Node suites passed 118 tests with two explicit live skips. A subsequent actual local run used the retained `cce4a4f9b` artifact, SHA-256 `be2771b9f2093cced55e8158d8d5a72ed35e6ac5e32edddb068daa45511e12ae`. All five collector predicates passed, all three candidates had typed absence proof, and no owned process remained. Its immutable private output SHA-256 is `210453778569f8c3adc3fb04e604e9accd6d928d4a40cd46eb187d9059a74b30`. No production request was made.

## Shared admission and metadata checkpoint

The reviewed shared Gate and credential-free comparator are integrated. At `3c51a86c7`, the production coordinator also connects configuration preflight and postflight to the shared reservation. Source identity is checked before metadata requests, and phase deadlines are checked after all admission waits. Receipt fields distinguish metadata requests, data requests and complete data observations; metadata-only production activity is still production activity.

Independent review approved the fixed coordinator at `0c640cae1`; the integrated coordinator and bridge tests passed 27 tests with three opt-in live skips. This approval excludes the subsequent CLI and owned-shadow extensions, which remain in preparation. The previous limits campaign permission is consumed, and no new production execution or parent promotion is claimed.
