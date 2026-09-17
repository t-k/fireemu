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
