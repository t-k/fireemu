import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { hostname, tmpdir, userInfo } from "node:os";
import { join, relative } from "node:path";
import { test } from "node:test";

const target = new URL("../pubsub-corpus/streaming-native-owned.mjs", import.meta.url);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const limits = Object.freeze({
  maxActions: 8,
  maxFrames: 4,
  maxFrameBytes: 32,
  maxOutgoingBytes: 256,
  maxIncomingBytes: 256,
  maxIncomingFrames: 4,
  maxChunks: 16,
  maxHeaderBytes: 1024,
  maxHeaderEvents: 8,
  maxHeaderPairs: 16,
  maxEvents: 32,
  maxNativeCallbacks: 64,
  maxChronologyRows: 96,
  maxJournalEntries: 144,
  maxEntryBytes: 8192,
  maxJournalBytes: 1179648,
  maxMessageBytes: 64,
  maxWriterRows: 144,
  maxWriterRecordBytes: 16384,
  maxWriterBytes: 2359296,
});
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
const frame = (payload) => {
  const body = Buffer.from(payload);
  const bytes = Buffer.alloc(body.length + 5);
  bytes.writeUInt32BE(body.length, 1);
  body.copy(bytes, 5);
  return bytes;
};
async function exports() {
  assert.ok(existsSync(target), "opaque actual-native factory is missing");
  return import(target.href);
}
async function fixture(options = {}) {
  const api = await exports();
  const deadlineAt = options.deadlineAt ?? performance.now() + 5000;
  const lease = await api.acquireOwnedLoopbackLease({ deadlineAt });
  return api.createOwnedNativeStreamingFixture({ lease, deadlineAt, limits, ...options });
}
async function using(options, callback) {
  const f = await fixture(options);
  try {
    await callback(f);
  } finally {
    const shutdown = await f.shutdown();
    assert.equal(shutdown.pendingOperations, 0);
    assert.equal(shutdown.pendingNativeOperations, 0);
    assert.equal(shutdown.fileClosed, true);
    assert.equal(shutdown.directoryClosed, true);
    assert.equal(shutdown.serverClosed, true);
    assert.equal(shutdown.sockets, 0);
    assert.equal(shutdown.sessions, 0);
    assert.equal(shutdown.crashDurability, "UNKNOWN");
  }
}
function bridge(f, options = {}) {
  return f.createBridge({
    guard: () => true,
    liveCheck: () => true,
    onFrame: () => {},
    ...options,
  });
}
function journalRecords(bytes) {
  return bytes
    .toString()
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line, index) => {
      const physical = JSON.parse(line);
      const body = Buffer.from(physical.bodyBase64, "base64");
      assert.equal(physical.index, index);
      assert.equal(physical.bodyBytes, body.length);
      assert.equal(physical.sha256, sha(body));
      assert.equal(body.toString("base64"), physical.bodyBase64);
      return { physical, body: JSON.parse(body) };
    });
}
function assertUnknown(report) {
  assert.equal(report.verdict, "uncertain");
  assert.ok(report.reasons.includes("pre-return-stream-window"));
}

test("native_owned_factory_rejects_unleased_and_foreign_capabilities_before_connect", async () => {
  const { createOwnedNativeStreamingFixture } = await exports();
  let stopped = 0;
  const foreign = {
    native: true,
    destroy() {
      stopped++;
    },
  };
  for (const lease of [undefined, true, {}, foreign]) {
    await assert.rejects(
      createOwnedNativeStreamingFixture({ lease, deadlineAt: performance.now() + 1000, limits }),
      /owned loopback lease/,
    );
  }
  assert.equal(stopped, 0);
  await using({}, async (f) => {
    assert.equal(f.boundarySnapshot().calls.length, 0);
    assert.throws(
      () =>
        f.createBridge({
          guard: () => true,
          liveCheck: () => true,
          onFrame: () => {},
          session: foreign,
        }),
      /closed bridge options/,
    );
    assert.equal(stopped, 0);
    assert.equal(f.boundarySnapshot().calls.length, 0);
    assert.equal(Object.hasOwn(f, "session"), false);
    assert.equal(Object.hasOwn(f, "stream"), false);
    assert.equal(f.boundarySnapshot().nativeCompleteness, "UNKNOWN");
    assert.throws(() => bridge(f, { credential: "synthetic-only" }), /credential-free/);
  });
});

test("actual_native_issue_boundaries_follow_committed_WAL_and_revocation_has_zero_peer_effects", async () => {
  for (const revoked of [false, true]) {
    const entered = deferred(),
      release = deferred();
    await using(
      {
        ioBarrier: async ({ operation, phase, rowIndex }) => {
          if (operation === "directory-sync" && phase === "before-syscall" && rowIndex === 0) {
            entered.resolve();
            await release.promise;
          }
        },
      },
      async (f) => {
        let live = true;
        const b = bridge(f, { liveCheck: () => live });
        const opening = b.open();
        await entered.promise;
        assert.deepEqual(f.boundarySnapshot().calls, []);
        assert.equal(f.peer.snapshot().streams, 0);
        live = !revoked;
        release.resolve();
        if (revoked) await assert.rejects(opening, /admission stopped/);
        else await opening;
        if (revoked) {
          assert.equal(
            f.boundarySnapshot().calls.some((c) => c.method === "request"),
            false,
          );
          assert.equal(f.peer.snapshot().streams, 0);
        } else {
          await f.peer.ready();
          await b.write(Buffer.from("a"));
          await b.halfClose();
          await f.peer.requestEnded();
          const calls = f.boundarySnapshot().calls;
          for (const method of ["request", "write", "end"]) {
            const pair = calls.filter((c) => c.method === method);
            assert.deepEqual(
              pair.map((c) => c.phase),
              ["entry", "return"],
            );
            assert.ok(pair[0].seq < pair[1].seq);
            assert.equal(pair[0].completion, "UNKNOWN");
          }
        }
        await b.done();
      },
    );
  }
});

test("real_h2_raw_headers_DATA_trailers_bind_to_readback_fsynced_native_receipts", async () => {
  for (const trailersOnly of [false, true]) {
    await using({}, async (f) => {
      const observed = [];
      const visible = deferred();
      const b = bridge(f, {
        onFrame: (candidate) => {
          observed.push(candidate);
          visible.resolve();
        },
      });
      await b.open();
      await f.peer.ready();
      if (trailersOnly)
        f.peer.respond(
          { ":status": 200, "content-type": "application/grpc", "grpc-status": "0" },
          true,
        );
      else {
        f.peer.respond();
        f.peer.send(frame("ok"));
        await f.awaitBarrier(visible.promise);
        await f.peer.finish({ "grpc-status": "0" });
      }
      await f.waitFor("end");
      const report = await b.done();
      assertUnknown(report);
      assert.equal(report.provenance.verdict, "peer-terminal");
      assert.equal(observed.length, trailersOnly ? 0 : 1);
      const records = journalRecords(await f.readJournal());
      const receipts = records.filter((r) => r.body.type === "receipt");
      for (const binding of report.bindings.filter((r) => r.state === "committed")) {
        const row = records[binding.journalIndex].body;
        assert.equal(row.nativeSeq, binding.seq);
        assert.equal(row.receipt.index, binding.receiptIndex);
        assert.equal(row.receipt.kind, binding.kind);
      }
      const native = f.boundarySnapshot().events;
      for (const { body } of receipts.filter((r) => r.body.receipt.rawHeaders)) {
        const receipt = body.receipt;
        const event = native.find(
          (e) =>
            e.kind === receipt.kind &&
            JSON.stringify(e.rawHeaders) === JSON.stringify(receipt.rawHeaders),
        );
        assert.ok(event, "WAL raw headers must originate from the actual native callback");
        assert.equal(event.flags, receipt.flags);
      }
      assert.ok(
        f.ioSnapshot().steps.some((s) => s.operation === "file-sync" && s.phase === "settled"),
      );
      assert.ok(
        f.ioSnapshot().steps.some((s) => s.operation === "directory-sync" && s.phase === "settled"),
      );
      assert.equal(f.ioSnapshot().crashDurability, "UNKNOWN");
    });
  }
});

test("real_rst_goaway_client_CANCEL_and_half_close_do_not_invent_grpc_status", async () => {
  for (const mode of ["reset", "goaway", "cancel", "half-close-reset"]) {
    await using({}, async (f) => {
      const b = bridge(f);
      await b.open();
      await f.peer.ready();
      if (mode === "half-close-reset") {
        await b.halfClose();
        await f.peer.requestEnded();
        f.peer.reset(8);
      } else if (mode === "reset") f.peer.reset(8);
      else if (mode === "goaway") f.peer.goaway(0);
      else await b.cancel();
      await f.waitFor(mode === "goaway" ? "goaway" : "stream-close");
      const report = await b.done();
      assertUnknown(report);
      assert.notEqual(report.provenance.verdict, "peer-terminal");
      const snapshot = f.boundarySnapshot();
      assert.ok(
        snapshot.events.some((e) => e.kind === (mode === "goaway" ? "goaway" : "stream-close")),
      );
      if (mode !== "goaway")
        assert.ok(snapshot.events.some((e) => e.kind === "stream-close" && e.rstCode === 8));
      const cancel = snapshot.calls.filter((c) => c.method === "close" && c.phase === "entry");
      assert.equal(cancel.length, 1);
      assert.equal(cancel[0].code, 8);
    });
  }
});

test("actual_native_containment_starts_inline_while_observer_is_held", async () => {
  const entered = deferred(),
    release = deferred();
  await using({}, async (f) => {
    const controller = new AbortController();
    const b = bridge(f, {
      signal: controller.signal,
      onFrame: async () => {
        entered.resolve();
        await release.promise;
      },
    });
    await b.open();
    await f.peer.ready();
    f.peer.respond();
    f.peer.send(frame("x"));
    await entered.promise;
    controller.abort();
    const snapshot = f.boundarySnapshot();
    assert.equal(
      snapshot.calls.filter((c) => c.method === "close" && c.phase === "entry").length,
      1,
    );
    assert.equal(
      snapshot.calls.filter((c) => c.method === "destroy" && c.phase === "entry").length,
      1,
    );
    assert.throws(() => b.write(Buffer.from("late")), /admission closed/);
    release.resolve();
    await b.done();
  });
});

test("real_callback_visibility_waits_for_actual_file_and_directory_sync_ack", async () => {
  const entered = deferred(),
    release = deferred(),
    visible = deferred();
  await using(
    {
      ioBarrier: async ({ operation, phase, body }) => {
        if (
          operation === "directory-sync" &&
          phase === "before-syscall" &&
          body?.type === "receipt" &&
          body.receipt.kind === "data"
        ) {
          entered.resolve();
          await release.promise;
        }
      },
    },
    async (f) => {
      let observed = 0;
      const b = bridge(f, {
        onFrame: () => {
          observed++;
          visible.resolve();
        },
      });
      await b.open();
      await f.peer.ready();
      f.peer.respond();
      f.peer.send(frame("x"));
      await entered.promise;
      assert.equal(observed, 0);
      assert.ok(f.ioSnapshot().pendingOperations > 0);
      release.resolve();
      await visible.promise;
      assert.equal(observed, 1);
      await b.done();
      journalRecords(await f.readJournal());
    },
  );
});

test("actual_native_fragmented_and_coalesced_frames_enforce_exact_cap_and_overflow", async () => {
  for (const mode of ["fragmented", "coalesced", "oversize", "frame-count", "byte-count"]) {
    const custom = {
      ...limits,
      maxIncomingFrames: mode === "frame-count" ? 1 : 4,
      maxIncomingBytes: mode === "byte-count" ? 7 : 256,
    };
    await using({ limits: custom }, async (f) => {
      const visible = [];
      const acknowledged = deferred();
      const b = bridge(f, {
        onFrame: (candidate) => {
          visible.push(candidate);
          if (visible.length === (mode === "fragmented" ? 1 : 2)) acknowledged.resolve();
        },
      });
      await b.open();
      await f.peer.ready();
      f.peer.respond();
      if (mode === "fragmented") {
        const wire = frame(Buffer.alloc(32, 120));
        f.peer.send(wire.subarray(0, 2));
        await f.waitFor("data", 1);
        f.peer.send(wire.subarray(2, 5));
        await f.waitFor("data", 2);
        f.peer.send(wire.subarray(5));
        await f.waitFor("data", 3);
      } else
        f.peer.send(
          mode === "oversize" ? frame(Buffer.alloc(33)) : Buffer.concat([frame("ab"), frame("cd")]),
        );
      if (["fragmented", "coalesced"].includes(mode)) {
        await f.awaitBarrier(acknowledged.promise);
        await f.peer.finish();
        await f.waitFor("end");
      } else await f.waitFor("stream-close");
      const report = await b.done();
      assertUnknown(report);
      if (mode === "fragmented") {
        assert.equal(visible.length, 1);
        assert.equal(visible[0].bodyBytes, 32);
      } else if (mode === "coalesced") assert.equal(visible.length, 2);
      else {
        assert.equal(visible.length, 0);
        assert.ok(report.reasons.includes("receipt-refused"));
      }
      assert.ok(report.receipts.framing.bytes <= custom.maxIncomingBytes);
      assert.ok(report.receipts.events <= custom.maxEvents);
    });
  }
});

test("real_observer_awaiting_bridge_write_makes_WAL_and_peer_progress", async () => {
  const observed = deferred();
  await using({}, async (f) => {
    let b;
    b = bridge(f, {
      onFrame: async () => {
        await b.write(Buffer.from("update"));
        observed.resolve();
      },
    });
    await b.open();
    await f.peer.ready();
    f.peer.respond();
    f.peer.send(frame("x"));
    await observed.promise;
    await b.halfClose();
    await f.peer.requestEnded();
    assert.equal(f.peer.snapshot().requestBytes, 11);
    await f.peer.finish();
    await f.waitFor("end");
    const report = await b.done();
    assertUnknown(report);
    assert.equal(report.receipts.acknowledgedFrames, 1);
    assert.equal(report.gate.unknownActions, 0);
  });
});

test("late_post_syscall_callback_settlement_never_mutates_returned_UNKNOWN", async () => {
  const entered = deferred(),
    release = deferred();
  let reached = false;
  const f = await fixture({
    deadlineAt: performance.now() + 400,
    ioBarrier: async ({ operation, phase, rowIndex }) => {
      if (operation === "file-sync" && phase === "after-syscall" && rowIndex === 0) {
        reached = true;
        entered.resolve();
        await release.promise;
      }
    },
  });
  try {
    const b = bridge(f);
    const opening = b.open();
    await f.awaitBarrier(Promise.race([entered.promise, opening.catch(() => {})]));
    assert.equal(
      reached,
      true,
      "post-syscall acknowledgement callback must precede open completion",
    );
    await assert.rejects(opening, /admission stopped/);
    const report = await b.done();
    const frozen = JSON.stringify(report);
    assert.equal(report.verdict, "uncertain");
    assert.equal(report.terminationRequired, true);
    assert.ok(f.ioSnapshot().pendingOperations > 0);
    assert.ok(
      f
        .ioSnapshot()
        .steps.some((step) => step.operation === "file-sync" && step.phase === "settled"),
    );
    assert.equal(f.ioSnapshot().pendingNativeOperations, 0);
    assert.ok(
      f
        .ioSnapshot()
        .systemCalls.some((call) => call.operation === "file-sync" && call.phase === "settled"),
    );
    release.resolve();
    const shutdown = await f.shutdown();
    assert.equal(shutdown.pendingOperations, 0);
    assert.equal(JSON.stringify(report), frozen);
    assert.equal(shutdown.crashDurability, "UNKNOWN");
  } finally {
    release.resolve();
    await f.shutdown();
  }
});

test("finite_lifecycle_model_checks_sixteen_hold_revoke_write_halfclose_schedules", async () => {
  let schedules = 0;
  for (const revoked of [false, true])
    for (const canceledBeforeCommit of [false, true])
      for (const write of [false, true])
        for (const halfClose of [false, true]) {
          const entered = deferred(),
            release = deferred();
          await using(
            {
              ioBarrier: async ({ operation, phase, rowIndex }) => {
                if (
                  operation === "directory-sync" &&
                  phase === "before-syscall" &&
                  rowIndex === 0
                ) {
                  entered.resolve();
                  await release.promise;
                }
              },
            },
            async (f) => {
              let live = true;
              const b = bridge(f, { liveCheck: () => live });
              const pending = b.open();
              await entered.promise;
              const model = { committed: false, live: true, closed: false, requests: 0 };
              assert.equal(f.peer.snapshot().streams, model.requests);
              live = !revoked;
              model.live = live;
              if (canceledBeforeCommit) {
                b.stopNow("client-cancel");
                model.closed = true;
              }
              release.resolve();
              model.committed = true;
              if (model.committed && model.live && !model.closed) model.requests++;
              if (revoked || canceledBeforeCommit)
                await assert.rejects(pending, /admission stopped/);
              else await pending;
              if (model.requests) {
                await f.peer.ready();
                if (write) await b.write(Buffer.from("model"));
                if (halfClose) {
                  await b.halfClose();
                  await f.peer.requestEnded();
                }
              }
              assert.equal(
                f
                  .boundarySnapshot()
                  .calls.filter((c) => c.method === "request" && c.phase === "entry").length,
                model.requests,
              );
              assert.equal(f.peer.snapshot().streams, model.requests);
              for (const [method, enabled] of [
                ["write", write],
                ["end", halfClose],
              ])
                assert.equal(
                  f
                    .boundarySnapshot()
                    .calls.filter((c) => c.method === method && c.phase === "entry").length,
                  model.requests && enabled ? 1 : 0,
                );
              await b.done();
              schedules++;
            },
          );
        }
  assert.equal(schedules, 16);
});

test("opaque_lease_is_single_use_and_expired_deadlines_cannot_create_owned_connections", async () => {
  const api = await exports();
  const deadlineAt = performance.now() + 5000;
  const lease = await api.acquireOwnedLoopbackLease({ deadlineAt });
  const f = await api.createOwnedNativeStreamingFixture({ lease, deadlineAt, limits });
  try {
    await assert.rejects(
      api.createOwnedNativeStreamingFixture({ lease, deadlineAt, limits }),
      /unused owned loopback lease/,
    );
    const b = bridge(f);
    assert.throws(() => bridge(f), /one owned bridge/);
    await b.done();
  } finally {
    await f.shutdown();
  }
  let unexpectedlyCreated;
  try {
    await assert.rejects(async () => {
      unexpectedlyCreated = await api.createOwnedNativeStreamingFixture({
        lease,
        deadlineAt,
        limits,
      });
    }, /unused owned loopback lease/);
  } finally {
    await unexpectedlyCreated?.shutdown();
  }
  await assert.rejects(
    api.acquireOwnedLoopbackLease({ deadlineAt: performance.now() - 1 }),
    /absolute deadline/,
  );
});

test("actual_FileHandle_short_zero_writes_and_closed_handle_syncs_never_ack_DATA", async () => {
  for (const ioFault of [
    "short-write",
    "zero-write",
    "close-file-before-sync",
    "close-directory-before-sync",
  ]) {
    await using({ ioFault }, async (f) => {
      let visible = 0;
      const b = bridge(f, {
        onFrame: () => {
          visible++;
        },
      });
      await b.open();
      await f.peer.ready();
      f.peer.respond();
      f.peer.send(frame("fault"));
      await f.waitFor("stream-close");
      const report = await b.done();
      assertUnknown(report);
      assert.equal(visible, 0);
      assert.equal(f.ioSnapshot().writer.failed, true);
      assert.ok(report.journal.unknownEntries > 0);
      const steps = f.ioSnapshot().steps;
      if (ioFault.includes("sync"))
        assert.ok(
          steps.some((step) => step.phase === "rejected" && step.operation.endsWith("sync")),
        );
    });
  }
});

test("failed_real_fsync_pipeline_barrier_never_releases_native_frame_visibility", async () => {
  for (const failingOperation of ["file-sync", "directory-sync"]) {
    const attempted = deferred();
    const visible = deferred();
    let reached = false;
    await using(
      {
        ioBarrier: async ({ operation, phase, body }) => {
          if (
            operation === failingOperation &&
            phase === "after-syscall" &&
            body?.type === "receipt" &&
            body.receipt.kind === "data"
          ) {
            reached = true;
            attempted.resolve();
            throw new Error("injected acknowledgement failure after actual syscall");
          }
        },
      },
      async (f) => {
        let observed = 0;
        const b = bridge(f, {
          onFrame: () => {
            observed++;
            visible.resolve();
          },
        });
        await b.open();
        await f.peer.ready();
        f.peer.respond();
        f.peer.send(frame("x"));
        await f.awaitBarrier(Promise.race([attempted.promise, visible.promise]));
        assert.equal(reached, true, "acknowledgement failure callback must run before visibility");
        await f.waitFor("stream-close");
        const report = await b.done();
        assertUnknown(report);
        assert.equal(observed, 0);
        assert.equal(f.ioSnapshot().writer.failed, true);
        assert.ok(report.journal.unknownEntries > 0);
      },
    );
  }
});

test("seeded_native_frame_property_matches_independent_length_and_payload_digest", async () => {
  let seed = 0x83a0521;
  const lengths = [0, 1, 31, 32];
  for (let index = 0; index < 8; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    lengths.push(seed % 33);
  }
  for (const length of lengths)
    await using({}, async (f) => {
      const payload = Buffer.from(
        Array.from({ length }, (_, index) => (index * 37 + length) % 256),
      );
      const visible = deferred();
      const b = bridge(f, { onFrame: (candidate) => visible.resolve(candidate) });
      await b.open();
      await f.peer.ready();
      f.peer.respond();
      f.peer.send(frame(payload));
      const candidate = await f.awaitBarrier(visible.promise);
      assert.equal(candidate.bodyBytes, length);
      assert.equal(candidate.bodySha256, sha(payload));
      assert.equal(candidate.bodyBase64, payload.toString("base64"));
      await b.done();
    });
});

test("actual_malformed_peer_status_and_nonidentity_encoding_remain_uncertain", async () => {
  for (const status of ["x", "0,0", "17", ["0", "0"]])
    await using({}, async (f) => {
      const b = bridge(f);
      await b.open();
      await f.peer.ready();
      f.peer.respond(
        { ":status": 200, "content-type": "application/grpc", "grpc-status": status },
        true,
      );
      await f.waitFor("end");
      const report = await b.done();
      assertUnknown(report);
      assert.equal(report.provenance.verdict, "uncertain");
      assert.equal(report.provenance.peerTerminal, null);
    });
  await using({}, async (f) => {
    const b = bridge(f);
    await b.open();
    await f.peer.ready();
    f.peer.respond({ ":status": 200, "content-type": "application/grpc", "grpc-encoding": "gzip" });
    await f.waitFor("stream-close");
    const report = await b.done();
    assertUnknown(report);
    assert.ok(report.reasons.includes("nonidentity-encoding"));
  });
});

test("actual_flood_contains_while_observer_is_held_and_keeps_four_reserved_stop_rows", async () => {
  const entered = deferred(),
    release = deferred();
  await using({ limits: { ...limits, maxIncomingFrames: 1 } }, async (f) => {
    const b = bridge(f, {
      onFrame: async () => {
        entered.resolve();
        await release.promise;
      },
    });
    await b.open();
    await f.peer.ready();
    f.peer.respond();
    f.peer.send(frame("a"));
    await f.awaitBarrier(entered.promise);
    f.peer.send(Buffer.concat([frame("b"), frame("c")]));
    await f.waitFor("stream-close");
    assert.equal(
      f
        .boundarySnapshot()
        .calls.filter((call) => call.method === "destroy" && call.phase === "entry").length,
      1,
    );
    release.resolve();
    const report = await b.done();
    assertUnknown(report);
    assert.ok(report.reasons.includes("receipt-refused"));
    assert.ok(report.receipts.events <= limits.maxEvents);
    const reserved = report.chronology.filter(
      (row) =>
        row.kind === "local-stop-entry" ||
        row.event === "local-stop-return" ||
        row.event === "native-close-ack",
    );
    assert.equal(reserved.length, 4);
    assert.ok(reserved.every((row) => row.committed));
  });
});

test("actual_native_callback_cap_causes_containment_without_frame_visibility", async () => {
  await using({ limits: { ...limits, maxNativeCallbacks: 1 } }, async (f) => {
    let visible = 0;
    const b = bridge(f, {
      onFrame: () => {
        visible++;
      },
    });
    await b.open();
    await f.peer.ready();
    f.peer.respond();
    f.peer.send(frame("x"));
    await f.waitFor("stream-close");
    const report = await b.done();
    assertUnknown(report);
    assert.equal(visible, 0);
    assert.ok(report.reasons.includes("native-callback-bound"));
    assert.equal(report.nativeCallbacks, 1);
    assert.ok(f.boundarySnapshot().events.length <= 5);
  });
});

test("actual_registry_reads_refuse_foreign_PID_owner_authority_and_expired_rows_without_connect", async () => {
  const api = await exports();
  const { DatabaseSync } = await import("node:sqlite");
  const directory = await mkdtemp(join(tmpdir(), "native-invalid-lease-"));
  const dbPath = join(directory, "invalid.sqlite");
  const keys = ["PORT", "PORT_REGISTRY_TOKEN", "PORT_REGISTRY_DB"];
  const original = keys.map((key) => process.env[key]);
  const cwd = await realpath(process.cwd());
  const token = "0".repeat(32);
  let base = {
    token,
    port: 12345,
    host: "127.0.0.1",
    pid: process.pid,
    service: "codex-pubsub-native-e3",
    agent_id: process.env.AGENT_ID ?? `${userInfo().username}@${hostname()}:${process.ppid}`,
    cwd,
    command: [
      "node",
      ...process.execArgv,
      relative(cwd, process.argv[1]),
      ...process.argv.slice(2),
    ].join(" "),
    expires_at: Math.floor(Date.now() / 1000) + 60,
  };
  if (original.every((value) => value !== undefined)) {
    const registry = new DatabaseSync(original[2], { readOnly: true });
    try {
      const selected = registry
        .prepare(
          "SELECT token, port, host, pid, service, agent_id, cwd, command, expires_at FROM reservations WHERE token = ?",
        )
        .get(original[1]);
      assert.equal(selected.pid, process.pid);
      assert.equal(selected.service, "codex-pubsub-native-e3");
      base = { ...selected, token };
    } finally {
      registry.close();
    }
  }
  // These invalid, exclusively owned databases test refusal only; no capability is used to bind.
  const poisons = [
    { pid: process.pid + 1 },
    { port: base.port === 65535 ? 65534 : base.port + 1 },
    { host: "localhost" },
    { service: "foreign-service" },
    { agent_id: "foreign-owner" },
    { cwd: directory },
    { command: "node foreign-process.mjs" },
    { token: "1".repeat(32) },
    { expires_at: Math.floor(Date.now() / 1000) - 1 },
  ];
  try {
    process.env.PORT = String(base.port);
    process.env.PORT_REGISTRY_TOKEN = token;
    process.env.PORT_REGISTRY_DB = dbPath;
    for (const poison of poisons) {
      const db = new DatabaseSync(dbPath);
      try {
        db.exec(
          "DROP TABLE IF EXISTS reservations; CREATE TABLE reservations (token TEXT, port INTEGER, host TEXT, pid INTEGER, service TEXT, agent_id TEXT, cwd TEXT, command TEXT, expires_at INTEGER)",
        );
        const row = { ...base, ...poison };
        db.prepare("INSERT INTO reservations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
          ...Object.values(row),
        );
      } finally {
        db.close();
      }
      await assert.rejects(
        api.acquireOwnedLoopbackLease({ deadlineAt: performance.now() + 1000 }),
        /owned loopback lease/,
      );
    }
  } finally {
    keys.forEach((key, index) => {
      if (original[index] === undefined) delete process.env[key];
      else process.env[key] = original[index];
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("owned_readback_is_bounded_and_settles_before_FileHandle_shutdown", async () => {
  const release = deferred();
  const f = await fixture({
    ioBarrier: async ({ operation, phase }) => {
      if (operation === "readback" && phase === "before-syscall") await release.promise;
    },
  });
  try {
    const b = bridge(f);
    await b.open();
    await f.peer.ready();
    await b.done();
    const read = f.readJournal();
    assert.equal(f.ioSnapshot().pendingOperations, 1);
    assert.throws(() => f.readJournal(), /one owned readback/);
    const stop = f.shutdown();
    release.resolve();
    journalRecords(await read);
    const shutdown = await stop;
    assert.equal(shutdown.pendingOperations, 0);
    assert.equal(shutdown.pendingNativeOperations, 0);
    assert.equal(shutdown.fileClosed, true);
  } finally {
    release.resolve();
    await f.shutdown();
  }
});

test("actual_native_syscall_Promise_is_tracked_before_the_IO_poll_settles_it", async () => {
  const entered = deferred();
  await using(
    {
      ioBarrier: ({ operation, phase, rowIndex }) => {
        if (operation === "file-sync" && phase === "before-syscall" && rowIndex === 0)
          entered.resolve();
      },
    },
    async (f) => {
      const b = bridge(f);
      const opening = b.open();
      await f.awaitBarrier(entered.promise);
      await Promise.resolve();
      const snapshot = f.ioSnapshot();
      assert.equal(snapshot.pendingNativeOperations, 1);
      assert.ok(
        snapshot.systemCalls.some(
          (call) => call.operation === "file-sync" && call.phase === "entry",
        ),
      );
      assert.equal(
        snapshot.systemCalls.some(
          (call) => call.operation === "file-sync" && call.phase === "settled",
        ),
        false,
      );
      await opening;
      await f.peer.ready();
      await b.done();
    },
  );
});
