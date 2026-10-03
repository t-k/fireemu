import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, open, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const target = new URL("../pubsub-corpus/streaming-bridge.mjs", import.meta.url);
const path = "/google.pubsub.v1.Subscriber/StreamingPull";
const limits = {
  maxActions: 4,
  maxFrames: 2,
  maxFrameBytes: 32,
  maxOutgoingBytes: 128,
  maxIncomingBytes: 128,
  maxIncomingFrames: 2,
  maxChunks: 4,
  maxHeaderBytes: 256,
  maxHeaderEvents: 4,
  maxHeaderPairs: 8,
  maxEvents: 8,
  maxNativeCallbacks: 16,
  maxChronologyRows: 32,
  maxJournalEntries: 48,
  maxEntryBytes: 4096,
  maxJournalBytes: 196608,
  maxMessageBytes: 64,
  maxWriterRows: 48,
  maxWriterRecordBytes: 8192,
  maxWriterBytes: 393216,
};
async function exports() {
  assert.ok(existsSync(target), "owned streaming bridge is missing");
  return import(target.href);
}
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((r, j) => {
    resolve = r;
    reject = j;
  });
  return { promise, resolve, reject };
};
const flush = async () => {
  for (let i = 0; i < 12; i++) await Promise.resolve();
};
function clockFixture() {
  const originalNow = Object.getOwnPropertyDescriptor(performance, "now");
  const originalSet = globalThis.setTimeout,
    originalClear = globalThis.clearTimeout;
  let now = 0,
    next = 0;
  const timers = new Map();
  Object.defineProperty(performance, "now", { configurable: true, value: () => now });
  globalThis.setTimeout = (callback, ms) => {
    const timer = {
      id: next++,
      at: now + Math.max(0, ms),
      callback,
      unref() {
        return this;
      },
    };
    timers.set(timer.id, timer);
    return timer;
  };
  globalThis.clearTimeout = (timer) => timers.delete(timer?.id);
  return {
    now: () => now,
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        const timer = [...timers.values()]
          .filter((t) => t.at <= end)
          .toSorted((a, b) => a.at - b.at)[0];
        if (!timer) break;
        now = timer.at;
        timers.delete(timer.id);
        timer.callback();
        await flush();
      }
      now = end;
      await flush();
      for (let pass = 0; ; pass++) {
        const due = [...timers.values()]
          .filter((timer) => timer.at <= now)
          .toSorted((a, b) => a.at - b.at)[0];
        if (!due) break;
        if (pass >= 32) throw new Error("clock due timers did not converge");
        timers.delete(due.id);
        due.callback();
        await flush();
      }
    },
    restore() {
      if (originalNow) Object.defineProperty(performance, "now", originalNow);
      else delete performance.now;
      globalThis.setTimeout = originalSet;
      globalThis.clearTimeout = originalClear;
    },
    timers,
  };
}
class Stream extends EventEmitter {
  writes = [];
  endCalls = 0;
  closeCalls = 0;
  acks = true;
  write(bytes) {
    this.writes.push(Buffer.from(bytes));
    this.onWrite?.();
    return this.writeResult ?? true;
  }
  end() {
    this.endCalls++;
    this.onEnd?.();
    return this;
  }
  close(code) {
    this.closeCalls++;
    assert.equal(code, 8);
    this.onCancel?.();
    if (this.acks) this.emit("close");
  }
}
class Session extends EventEmitter {
  stream = new Stream();
  requests = [];
  destroyCalls = 0;
  acks = true;
  request(headers) {
    this.requests.push({ ...headers });
    this.onRequest?.();
    return this.stream;
  }
  destroy() {
    this.destroyCalls++;
    this.onDestroy?.();
    if (this.acks) this.emit("close");
  }
}
async function fixture(extra = {}) {
  const { createOwnedStreamingBridge } = await exports();
  const session = extra.session ?? new Session();
  const rows = [],
    frames = [];
  const bridge = createOwnedStreamingBridge({
    session,
    authority: "http://127.0.0.1:1",
    path,
    metadata: {},
    deadlineAt: performance.now() + 100,
    limits,
    guard: () => {},
    liveCheck: () => true,
    write: async (row) => {
      rows.push(structuredClone(row));
    },
    onFrame: (candidate) => {
      frames.push(candidate);
    },
    ...extra,
  });
  return { bridge, session, rows, frames };
}
function decoded(rows) {
  return rows.map((row) => JSON.parse(Buffer.from(row.bodyBase64, "base64").toString()));
}
function frame(bytes) {
  const header = Buffer.alloc(5);
  header.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([header, bytes]);
}
async function withClock(work) {
  const clock = clockFixture();
  try {
    await work(clock);
  } finally {
    clock.restore();
  }
}
const terminal = (stream, flags = 0) => stream.emit("trailers", {}, flags, ["grpc-status", "0"]);

test("durable_intent_and_final_live_authority_precede_every_native_effect", () =>
  withClock(async (clock) => {
    for (const action of ["open", "write", "halfClose", "cancel"]) {
      const held = deferred();
      let block = false;
      const f = await fixture({ write: (_row) => (block ? held.promise : Promise.resolve()) });
      if (action !== "open") await f.bridge.open();
      block = true;
      const started = action === "write" ? f.bridge.write(Buffer.from("x")) : f.bridge[action]();
      await flush();
      assert.equal(
        action === "open"
          ? f.session.requests.length
          : action === "write"
            ? f.session.stream.writes.length
            : action === "halfClose"
              ? f.session.stream.endCalls
              : f.session.stream.closeCalls,
        0,
      );
      held.resolve();
      await started;
      assert.equal(
        action === "open"
          ? f.session.requests.length
          : action === "write"
            ? f.session.stream.writes.length
            : action === "halfClose"
              ? f.session.stream.endCalls
              : f.session.stream.closeCalls,
        1,
      );
      await f.bridge.done();
    }
    let live = true;
    const f = await fixture({
      liveCheck: () => live,
      write: async () => {
        live = false;
      },
    });
    await assert.rejects(f.bridge.open());
    assert.equal(f.session.requests.length, 0);
    await f.bridge.done();
    const deny = await fixture({
      guard: () => {
        throw new Error("deny");
      },
    });
    await assert.rejects(deny.bridge.open());
    assert.equal(deny.session.requests.length, 0);
    await deny.bridge.done();
    assert.equal(clock.now(), 0);
  }));

test("every_component_and_drain_keeps_one_absolute_deadline", () =>
  withClock(async (clock) => {
    const f = await fixture();
    await clock.advance(30);
    await f.bridge.open();
    const timeout = f.session.requests[0]["grpc-timeout"];
    const scale = { n: 1e-6, u: 1e-3, m: 1, S: 1000, M: 60000, H: 3600000 };
    assert.ok(Number(timeout.slice(0, -1)) * scale[timeout.at(-1)] <= 70);
    terminal(f.session.stream);
    await flush();
    await clock.advance(70);
    assert.throws(() => f.bridge.write(Buffer.from("x")));
    const report = await f.bridge.done();
    for (const key of ["gate", "receipts", "journal"]) assert.equal(report[key].deadlineAt, 100);
    assert.equal(report.terminationRequired, true);
  }));

test("containment_starts_in_the_triggering_stack_while_callbacks_are_held", () =>
  withClock(async (clock) => {
    for (const heldKind of ["guard", "write", "observer"]) {
      const held = deferred(),
        signal = new AbortController();
      let holding = false;
      const f = await fixture({
        signal: signal.signal,
        guard: () => (holding && heldKind === "guard" ? held.promise : undefined),
        write: () => (holding && heldKind === "write" ? held.promise : Promise.resolve()),
        onFrame: () => (heldKind === "observer" ? held.promise : undefined),
      });
      await f.bridge.open();
      holding = true;
      let action;
      if (heldKind !== "observer") {
        action = f.bridge.write(Buffer.from("x"));
        action.catch(() => {});
      } else {
        f.session.stream.emit("data", frame(Buffer.from("x")));
      }
      await flush();
      signal.abort();
      assert.equal(f.session.stream.closeCalls, 1);
      assert.equal(f.session.destroyCalls, 1);
      assert.throws(() => f.bridge.write(Buffer.from("y")));
      f.bridge.stopNow("deadline");
      assert.equal(f.session.destroyCalls, 1);
      const pending = f.bridge.done();
      await flush();
      await clock.advance(101);
      const report = await pending;
      assert.equal(report.terminationRequired, true);
      const copy = structuredClone(report);
      held.resolve();
      await flush();
      if (action) await action.catch(() => {});
      assert.deepEqual(report, copy);
    }
    const signal = new AbortController();
    signal.abort();
    const aborted = await fixture({ signal: signal.signal });
    assert.equal(aborted.session.destroyCalls, 1);
    assert.throws(() => aborted.bridge.open());
    await aborted.bridge.done();
  }));

test("native_entry_inline_event_and_return_keep_order_despite_late_commits", () =>
  withClock(async () => {
    const f = await fixture();
    await f.bridge.open();
    f.session.stream.onWrite = () => terminal(f.session.stream);
    await f.bridge.write(Buffer.from("x"));
    const report = await f.bridge.done();
    const entry = report.chronology.find(
      (row) => row.kind === "marker" && row.event === "issue-entry" && row.seq > 1,
    );

    const peer = report.chronology.find((row) => row.kind === "trailers");
    const returned = report.chronology.find(
      (row) => row.kind === "marker" && row.event === "issue-return" && row.seq > peer.seq,
    );
    assert.ok(entry.seq < peer.seq && peer.seq < returned.seq);
    assert.equal(new Set(report.chronology.map((row) => row.seq)).size, report.chronology.length);
    assert.equal(report.provenance.verdict, "peer-terminal");
    const thrown = await fixture();
    await thrown.bridge.open();
    thrown.session.stream.onWrite = () => {
      terminal(thrown.session.stream);
      throw new Error("native");
    };
    await assert.rejects(thrown.bridge.write(Buffer.from("x")));
    assert.equal((await thrown.bridge.done()).verdict, "uncertain");
    const lost = await fixture();
    lost.session.onRequest = () => terminal(lost.session.stream);
    await lost.bridge.open();
    assert.ok((await lost.bridge.done()).reasons.includes("pre-return-stream-window"));
  }));

test("peer_terminal_and_local_cancel_races_preserve_separate_authority", () =>
  withClock(async () => {
    const before = await fixture();
    await before.bridge.open();
    terminal(before.session.stream);
    await before.bridge.cancel();
    const a = await before.bridge.done();
    assert.equal(a.provenance.verdict, "peer-terminal");
    assert.equal(a.provenance.localCause, "client-cancel");
    assert.ok(a.provenance.peerTerminalSeq < a.provenance.localCauseSeq);
    const after = await fixture();
    await after.bridge.open();
    after.session.stream.onCancel = () => terminal(after.session.stream);
    await after.bridge.cancel();
    const b = await after.bridge.done();
    assert.equal(b.provenance.verdict, "uncertain");
    assert.ok(b.provenance.reasons.includes("peer-after-local-stop"));
    assert.ok(b.provenance.localCauseSeq < b.provenance.peerTerminalSeq);
  }));

test("floods_respect_every_shared_bound_and_reserved_stop_capacity", () =>
  withClock(async (clock) => {
    const { createOwnedStreamingBridge } = await exports();
    for (const key of Object.keys(limits)) {
      for (const value of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])
        assert.throws(() =>
          createOwnedStreamingBridge({
            session: new Session(),
            authority: "http://localhost:1",
            path,
            deadlineAt: 100,
            limits: { ...limits, [key]: value },
            guard: () => {},
            liveCheck: () => true,
            write: () => {},
            onFrame: () => {},
          }),
        );
    }
    for (const [key, value] of [
      ["maxJournalEntries", 47],
      ["maxChronologyRows", 31],
      ["maxJournalBytes", 1000],
      ["maxEntryBytes", 100],
      ["maxWriterRows", 47],
      ["maxWriterRecordBytes", 100],
      ["maxWriterBytes", 100],
    ])
      assert.throws(() =>
        createOwnedStreamingBridge({
          session: new Session(),
          authority: "http://localhost:1",
          path,
          deadlineAt: 100,
          limits: { ...limits, [key]: value },
          guard: () => {},
          liveCheck: () => true,
          write: () => {},
          onFrame: () => {},
        }),
      );
    const held = deferred();
    let block = false;
    const f = await fixture({ write: () => (block ? held.promise : Promise.resolve()) });
    await f.bridge.open();
    block = true;
    for (let i = 0; i < 50; i++) f.session.stream.emit("data", Buffer.alloc(0));
    assert.equal(f.session.destroyCalls, 1);
    const pending = f.bridge.done();
    await clock.advance(101);
    const report = await pending;
    assert.ok(report.chronology.length <= limits.maxChronologyRows);
    assert.ok(report.bindings.length <= limits.maxEvents);
    assert.ok(report.nativeCallbacks <= limits.maxNativeCallbacks);
    assert.ok(report.lostCallbacks > 0);
    held.resolve();
    await flush();
  }));

test("observer_awaiting_write_progresses_without_holding_the_journal", () =>
  withClock(async () => {
    let bridge;
    const f = await fixture({
      onFrame: async () => {
        await bridge.write(Buffer.from("answer"));
      },
    });
    bridge = f.bridge;
    await bridge.open();
    f.session.stream.emit("data", frame(Buffer.from("question")));
    for (let i = 0; i < 10; i++) await flush();
    assert.equal(f.session.stream.writes.length, 1);
    const report = await bridge.done();
    assert.equal(report.receipts.acknowledgedFrames, 1);
  }));

test("only_ticket_bound_native_terminal_metadata_can_supply_peer_status", () =>
  withClock(async () => {
    for (const headers of [
      ["grpc-status", "0"],
      ["grpc-status", "0", "grpc-status", "0"],
      [],
      ["grpc-status", "17"],
    ]) {
      const f = await fixture();
      await f.bridge.open();
      f.session.stream.emit("response", {}, 1, headers);
      await flush();
      const report = await f.bridge.done();
      assert.equal(
        report.provenance.verdict,
        headers.length === 2 && headers[1] === "0" ? "peer-terminal" : "uncertain",
      );
      const binding = report.bindings.find((item) => item.kind === "response");
      assert.equal(binding.state, "committed");
      assert.ok(Number.isSafeInteger(binding.journalIndex));
      assert.equal(report.verdict, "uncertain");
    }
    const f = await fixture({ credential: "abcdefghTOKEN" });
    await f.bridge.open();
    f.session.stream.emit("response", {}, 0, ["grpc-encoding", "gzip"]);
    f.session.stream.emit("data", frame(Buffer.from("abcdefgh")));
    assert.equal(f.session.destroyCalls, 1);
    const report = await f.bridge.done();
    assert.equal(report.receipts.framing.bytes, 0);
    assert.equal(report.chronology.filter((row) => row.kind === "data").length, 0);
    assert.ok(report.reasons.includes("nonidentity-data-refused"));
    assert.ok(report.reasons.includes("nonidentity-encoding"));
    assert.ok(!decoded(f.rows).some((row) => JSON.stringify(row).includes("abcdefgh")));
  }));

test("false_write_throws_and_pending_done_never_retry_or_fabricate_completion", () =>
  withClock(async (clock) => {
    const f = await fixture();
    f.session.stream.writeResult = false;
    await f.bridge.open();
    await f.bridge.write(Buffer.from("x"));
    assert.equal(f.session.stream.writes.length, 1);
    const done = await f.bridge.done();
    assert.equal(done.gate.issuedActions, 2);
    assert.equal(done.native.streamClosed, true);
    assert.equal(done.native.sessionClosed, true);
    const held = await fixture();
    held.session.stream.acks = false;
    held.session.acks = false;
    await held.bridge.open();
    const pending = held.bridge.done();
    assert.equal(held.session.destroyCalls, 1);
    await clock.advance(101);
    const report = await pending;
    assert.equal(report.terminationRequired, true);
    assert.equal(report.native.streamClosed, false);
    assert.equal(report.native.sessionClosed, false);
    const snapshot = structuredClone(report);
    held.session.stream.emit("close");
    held.session.emit("close");
    await flush();
    assert.deepEqual(report, snapshot);
  }));

test("receipt_admission_tickets_bind_unique_native_callbacks_under_reentrancy", () =>
  withClock(async () => {
    for (const raw of [Buffer.from([1, 0, 0, 0, 0]), Buffer.from("abcdefgh")]) {
      const f = await fixture({ credential: "abcdefghTOKEN" });
      await f.bridge.open();
      f.session.stream.emit("data", raw);
      const report = await f.bridge.done();
      const binding = report.bindings.find((row) => row.kind === "data");
      assert.equal(binding.state, raw[0] === 1 ? "committed" : "raw-absent");
      assert.equal(report.provenance.peerTerminal, null);
    }
    const f = await fixture();
    await f.bridge.open();
    terminal(f.session.stream);
    terminal(f.session.stream);
    const report = await f.bridge.done();
    const bindings = report.bindings.filter((row) => row.kind === "trailers");
    assert.equal(bindings.length, 2);
    assert.notEqual(bindings[0].seq, bindings[1].seq);
    assert.notEqual(bindings[0].journalIndex, bindings[1].journalIndex);
    assert.ok(report.provenance.reasons.includes("second-terminal"));
  }));

test("authority_metadata_and_credentials_have_closed_finite_admission", () =>
  withClock(async () => {
    const { createOwnedStreamingBridge } = await exports();
    const args = {
      session: new Session(),
      authority: "http://localhost:1",
      path,
      deadlineAt: performance.now() + 100,
      limits,
      guard: () => {},
      liveCheck: () => true,
      write: () => {},
      onFrame: () => {},
    };
    for (const authority of [
      "https://other.example",
      "https://pubsub.googleapis.com/",
      "http://user@localhost:1",
      "http://localhost:1/x",
      "http://localhost:1?x",
      "http://localhost:1#x",
      "http://127.0.0.2:1",
    ])
      assert.throws(() => createOwnedStreamingBridge({ ...args, authority }));
    for (const metadata of [
      { ":path": path },
      { Authorization: "x" },
      { authorization: "Bearer wrong" },
      { "x-goog-user-project": "x\n" },
      { "x-goog-user-project": "a".repeat(16392) },
    ])
      assert.throws(() => createOwnedStreamingBridge({ ...args, metadata }));
    for (const accessor of [false, true]) {
      const metadata = {};
      let calls = 0;
      Object.defineProperty(
        metadata,
        "other",
        accessor
          ? {
              get() {
                calls++;
                throw Error("getter");
              },
            }
          : { value: "x" },
      );
      assert.throws(() => createOwnedStreamingBridge({ ...args, metadata }));
      assert.equal(calls, 0);
    }
    const credential = "a".repeat(16384);
    const f = await fixture({
      authority: "https://pubsub.googleapis.com",
      credential,
      metadata: { authorization: `Bearer ${credential}` },
    });
    await f.bridge.open();
    assert.equal(f.session.requests[0].authorization.length, 16391);
    await f.bridge.done();
    assert.ok(!decoded(f.rows).some((row) => JSON.stringify(row).includes(credential)));
  }));

test("real_tempfile_writer_acknowledges_only_after_full_write_and_both_fsyncs", async () => {
  const { createOwnedJournalWriter } = await exports();
  const directory = await mkdtemp(join(tmpdir(), "owned-bridge-writer-"));
  let file, directoryHandle;
  try {
    file = await open(join(directory, "wal"), "wx");
    directoryHandle = await open(directory, "r");
    const steps = [];
    const bytes = Buffer.from('{"type":"fixture"}');
    const row = {
      index: 0,
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const writer = createOwnedJournalWriter({
      fileHandle: {
        async write(...args) {
          steps.push("write");
          return file.write(...args);
        },
        async sync() {
          steps.push("file-sync");
          await file.sync();
        },
      },
      directoryHandle: {
        async sync() {
          steps.push("directory-sync");
          await directoryHandle.sync();
        },
      },
      deadlineAt: performance.now() + 1000,
      limits: { maxWriterRows: 2, maxWriterRecordBytes: 1024, maxWriterBytes: 2048 },
    });
    await writer.write(row, {});
    steps.push("ack");
    assert.deepEqual(steps, ["write", "file-sync", "directory-sync", "ack"]);
    const stored = JSON.parse((await readFile(join(directory, "wal"))).toString());
    assert.deepEqual(stored, row);
    assert.equal(
      createHash("sha256").update(Buffer.from(stored.bodyBase64, "base64")).digest("hex"),
      row.sha256,
    );
  } finally {
    await file?.close();
    await directoryHandle?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("writer_short_zero_failed_sync_overlap_order_and_deadline_never_ack", () =>
  withClock(async (clock) => {
    const { createOwnedJournalWriter } = await exports();
    const bytes = Buffer.from("x"),
      row = {
        index: 0,
        bodyBase64: bytes.toString("base64"),
        bodyBytes: 1,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
    const writerLimits = { maxWriterRows: 2, maxWriterRecordBytes: 1024, maxWriterBytes: 2048 };
    for (const failure of ["short", "zero", "file-sync", "directory-sync"]) {
      const writer = createOwnedJournalWriter({
        deadlineAt: 100,
        limits: writerLimits,
        fileHandle: {
          async write(buffer) {
            return {
              bytesWritten:
                failure === "short" ? buffer.length - 1 : failure === "zero" ? 0 : buffer.length,
            };
          },
          async sync() {
            if (failure === "file-sync") throw Error("sync");
          },
        },
        directoryHandle: {
          async sync() {
            if (failure === "directory-sync") throw Error("sync");
          },
        },
      });
      await assert.rejects(writer.write(row, {}));
      assert.equal(writer.report().acknowledgedRows, 0);
    }
    const held = deferred();
    const writer = createOwnedJournalWriter({
      deadlineAt: 100,
      limits: writerLimits,
      fileHandle: { write: () => held.promise, sync: () => Promise.resolve() },
      directoryHandle: { sync: () => Promise.resolve() },
    });
    const first = writer.write(row, {});
    first.catch(() => {});
    const overlapping = writer.write({ ...row, index: 1 }, {});
    overlapping.catch(() => {});
    assert.equal(writer.report().failed, true);
    assert.equal(writer.report().attemptedRows, 1);
    await assert.rejects(overlapping);
    await clock.advance(101);
    await assert.rejects(first);
    held.resolve({ bytesWritten: 999 });
    await flush();
    assert.equal(writer.report().acknowledgedRows, 0);
  }));

test("generated_owned_session_interleavings_match_an_independent_counter_model", () =>
  withClock(async () => {
    const reached = new Set();
    let seed = 0x35fe6;
    const random = (n) => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return (seed >>> 0) % n;
    };
    for (let i = 0; i < 96; i++) {
      const before = i % 2 === 0,
        kind = i % 3;
      const f = await fixture();
      await f.bridge.open();
      let expectedWrites = 0,
        expectedEnd = 0;
      const actions = random(3);
      for (let a = 0; a < actions; a++) {
        if (kind === 0) {
          f.session.stream.writeResult = false;
          await f.bridge.write(Buffer.from([a]));
          expectedWrites++;
          reached.add("false-write");
        } else if (kind === 1) {
          await f.bridge.halfClose();
          expectedEnd++;
          break;
        }
      }
      if (before) {
        terminal(f.session.stream);
        reached.add("peer-before-local");
      }
      if (kind === 2) {
        f.session.stream.onCancel = () => {
          terminal(f.session.stream);
          reached.add("inline-event");
        };
        await f.bridge.cancel();
        reached.add("peer-after-local");
      }
      const report = await f.bridge.done();
      assert.equal(f.session.requests.length, 1);
      assert.equal(f.session.stream.writes.length, expectedWrites);
      assert.equal(f.session.stream.endCalls, expectedEnd);
      assert.equal(f.session.stream.closeCalls, 1);
      assert.equal(f.session.destroyCalls, 1);
      assert.equal(report.verdict, "uncertain");
      assert.ok(report.reasons.includes("pre-return-stream-window"));
      assert.equal(new Set(report.chronology.map((row) => row.seq)).size, report.chronology.length);
    }
    assert.deepEqual([...reached].toSorted(), [
      "false-write",
      "inline-event",
      "peer-after-local",
      "peer-before-local",
    ]);
  }));

test("a_pending_live_check_and_constructor_native_events_cannot_escape_ownership", () =>
  withClock(async (clock) => {
    const held = deferred();
    held.promise.catch(() => {});
    const f = await fixture({ liveCheck: () => held.promise });
    await assert.rejects(f.bridge.open());
    const pending = f.bridge.done();
    await flush();
    await clock.advance(101);
    const report = await pending;
    assert.ok(report.gate.pendingCallbacks.some((id) => id.endsWith(":async-live")));
    assert.equal(f.session.requests.length, 0);
    assert.equal(report.terminationRequired, true);
    assert.equal(report.verdict, "uncertain");
    assert.ok(report.reasons.includes("unresolved-owned-work"));
    const snapshot = structuredClone(report);
    held.reject(new Error("late denied authority"));
    await flush();
    assert.deepEqual(report, snapshot);
    const session = new Session();
    const nativeOn = session.on;
    session.on = function (event, callback) {
      const result = nativeOn.call(this, event, callback);
      if (event === "error") this.emit("error", new Error("constructor event"));
      return result;
    };
    const constructed = await fixture({ session });
    assert.equal(session.destroyCalls, 1);
    assert.throws(() => constructed.bridge.open());
    const closed = await constructed.bridge.done();
    assert.ok(closed.reasons.includes("constructor-native-error"));
  }));

test("synchronous_marker_stop_prevents_native_write_and_end", () =>
  withClock(async () => {
    for (const action of ["write", "halfClose"]) {
      const f = await fixture();
      await f.bridge.open();
      const original = JSON.stringify;
      let entered = false;
      JSON.stringify = function (value, ...args) {
        if (value?.type === "native" && value.row?.event === "issue-entry" && !entered) {
          entered = true;
          f.bridge.stopNow("abort");
        }
        return original(value, ...args);
      };
      try {
        await assert.rejects(
          action === "write" ? f.bridge.write(Buffer.from("x")) : f.bridge.halfClose(),
        );
      } finally {
        JSON.stringify = original;
      }
      assert.equal(entered, true);
      assert.equal(f.session.stream.writes.length, 0);
      assert.equal(f.session.stream.endCalls, 0);
      await f.bridge.done();
    }
  }));

test("wire_and_receipt_caps_admit_exactly_the_bound_and_stop_on_the_next_item", () =>
  withClock(async () => {
    for (const [key, cap, payload] of [
      ["maxFrameBytes", 1, Buffer.from("a")],
      ["maxOutgoingBytes", 6, Buffer.from("a")],
      ["maxFrames", 1, Buffer.from("a")],
      ["maxActions", 2, Buffer.from("a")],
    ]) {
      const f = await fixture({ limits: { ...limits, [key]: cap } });
      await f.bridge.open();
      await f.bridge.write(payload);
      assert.equal(f.session.stream.writes.length, 1);
      assert.throws(() =>
        f.bridge.write(key === "maxFrameBytes" ? Buffer.from("ab") : Buffer.alloc(0)),
      );
      assert.equal(f.session.stream.writes.length, 1);
      assert.equal(f.session.destroyCalls, 1);
      await f.bridge.done();
    }
    const cases = [
      {
        key: "maxIncomingBytes",
        cap: 6,
        first: frame(Buffer.from("a")),
        extra: frame(Buffer.from("aa")),
        reason: "total-bound",
      },
      {
        key: "maxFrameBytes",
        cap: 1,
        first: frame(Buffer.from("a")),
        extra: frame(Buffer.from("aa")),
        reason: "frame-bound",
      },
      {
        key: "maxIncomingFrames",
        cap: 1,
        first: frame(Buffer.from("a")),
        extra: Buffer.concat([frame(Buffer.from("a")), frame(Buffer.from("b"))]),
        reason: "frame-count",
      },
    ];
    for (const item of cases) {
      for (const over of [false, true]) {
        const f = await fixture({ limits: { ...limits, [item.key]: item.cap } });
        await f.bridge.open();
        f.session.stream.emit("data", over ? item.extra : item.first);
        for (let i = 0; i < 6; i++) await flush();
        assert.equal(f.frames.length, over ? 0 : 1);
        const report = await f.bridge.done();
        if (over) assert.equal(report.receipts.framing.reason, item.reason);
      }
    }
    for (const key of ["maxChunks", "maxEvents", "maxNativeCallbacks"]) {
      const f = await fixture({ limits: { ...limits, [key]: 1 } });
      await f.bridge.open();
      f.session.stream.emit("data", Buffer.alloc(0));
      await flush();
      assert.equal(f.session.destroyCalls, 0);
      f.session.stream.emit("data", Buffer.alloc(0));
      assert.equal(f.session.destroyCalls, 1);
      const report = await f.bridge.done();
      assert.ok(report.lostCallbacks > 0);
    }
    for (const key of ["maxHeaderPairs", "maxHeaderBytes", "maxHeaderEvents"]) {
      for (const over of [false, true]) {
        const cap = key === "maxHeaderBytes" ? 12 : 1;
        const f = await fixture({ limits: { ...limits, [key]: cap } });
        await f.bridge.open();
        if (key === "maxHeaderEvents" && over)
          f.session.stream.emit("response", {}, 0, ["grpc-status", "0"]);
        f.session.stream.emit(
          "trailers",
          {},
          0,
          key === "maxHeaderPairs" && over
            ? ["grpc-status", "0", "x", "y"]
            : ["grpc-status", key === "maxHeaderBytes" && over ? "00" : "0"],
        );
        await flush();
        const report = await f.bridge.done();
        assert.equal(report.provenance.verdict, over ? "uncertain" : "peer-terminal");
      }
    }
  }));

test("metadata_total_bytes_and_every_own_descriptor_are_bounded_before_effects", () =>
  withClock(async () => {
    const { createOwnedStreamingBridge } = await exports();
    const session = new Session();
    const args = {
      session,
      authority: "http://localhost:1",
      path,
      deadlineAt: 100,
      limits,
      guard: () => {},
      liveCheck: () => true,
      write: async () => {},
      onFrame: () => {},
    };
    const first = "x-goog-request-params",
      second = "x-goog-user-project";
    const metadata = {
      [first]: "a".repeat(16391),
      [second]: "b".repeat(32768 - first.length - second.length - 16391),
    };
    const f = await fixture({ metadata });
    await f.bridge.open();
    assert.equal(
      Object.entries(metadata).reduce(
        (n, [k, v]) => n + Buffer.byteLength(k) + Buffer.byteLength(v),
        0,
      ),
      32768,
    );
    await f.bridge.done();
    assert.throws(() =>
      createOwnedStreamingBridge({
        ...args,
        metadata: { ...metadata, [second]: metadata[second] + "b" },
      }),
    );
    for (const key of [first, "unknown", Symbol("hidden")]) {
      for (const enumerable of [false, true]) {
        let calls = 0;
        const object = {};
        Object.defineProperty(object, key, {
          enumerable,
          get() {
            calls++;
            throw Error("unreadable");
          },
        });
        assert.throws(() => createOwnedStreamingBridge({ ...args, metadata: object }));
        assert.equal(calls, 0);
      }
    }
    const ownData = {};
    Object.defineProperty(ownData, first, { value: "a" });
    const accepted = await fixture({ metadata: ownData });
    await accepted.bridge.open();
    assert.equal(accepted.session.requests[0][first], "a");
    await accepted.bridge.done();
    assert.equal(session.requests.length, 0);
    assert.equal(session.destroyCalls, 0);
  }));

test("writer_binding_order_and_physical_caps_fail_before_any_file_effect", () =>
  withClock(async (clock) => {
    const { createOwnedJournalWriter } = await exports();
    const body = Buffer.from("x");
    const row = {
      index: 0,
      bodyBase64: body.toString("base64"),
      bodyBytes: body.length,
      sha256: createHash("sha256").update(body).digest("hex"),
    };
    const recordBytes = Buffer.byteLength(JSON.stringify(row) + "\n");
    function writer(extra = {}) {
      const effects = [];
      const ownedWriter = createOwnedJournalWriter({
        deadlineAt: 100,
        limits: {
          maxWriterRows: 1,
          maxWriterRecordBytes: recordBytes,
          maxWriterBytes: recordBytes,
        },
        fileHandle: {
          async write(bytes, offset, length, position) {
            effects.push(["write", offset, length, position]);
            return { bytesWritten: bytes.length };
          },
          async sync() {
            effects.push(["file-sync"]);
          },
        },
        directoryHandle: {
          async sync() {
            effects.push(["directory-sync"]);
          },
        },
        ...extra,
      });
      return { writer: ownedWriter, effects };
    }
    const exact = writer({
      limits: {
        maxWriterRows: 1,
        maxWriterRecordBytes: recordBytes,
        maxWriterBytes: recordBytes * 2,
      },
    });
    await exact.writer.write(row);
    assert.equal(exact.writer.report().totalBytes, recordBytes);
    assert.equal(exact.writer.report().acknowledgedRows, 1);
    await assert.rejects(exact.writer.write({ ...row, index: 1 }));
    assert.equal(exact.effects.length, 3);
    for (const bad of [
      { ...row, index: 1 },
      { ...row, index: -1 },
      { ...row, bodyBase64: "eA" },
      { ...row, bodyBytes: 2 },
      { ...row, sha256: "0".repeat(64) },
      { ...row, unknown: true },
      Object.defineProperty({ ...row }, "hidden", { value: true }),
    ]) {
      const f = writer();
      await assert.rejects(f.writer.write(bad));
      assert.deepEqual(f.effects, []);
      assert.equal(f.writer.report().acknowledgedRows, 0);
    }
    for (const key of ["maxWriterRecordBytes", "maxWriterBytes"]) {
      const f = writer({
        limits: {
          maxWriterRows: 1,
          maxWriterRecordBytes: recordBytes,
          maxWriterBytes: recordBytes,
          [key]: recordBytes - 1,
        },
      });
      await assert.rejects(f.writer.write(row));
      assert.deepEqual(f.effects, []);
    }
    const aborted = writer();
    await assert.rejects(aborted.writer.write(row, { signal: AbortSignal.abort() }));
    assert.deepEqual(aborted.effects, []);
    const sync = deferred();
    const stages = [];
    const late = writer({
      fileHandle: {
        async write(bytes) {
          stages.push("write");
          return { bytesWritten: bytes.length };
        },
        sync() {
          stages.push("file-sync");
          return sync.promise;
        },
      },
      directoryHandle: {
        async sync() {
          stages.push("directory-sync");
        },
      },
    });
    const pending = late.writer.write(row);
    const rejected = assert.rejects(pending);
    await flush();
    await clock.advance(101);
    await rejected;
    sync.resolve();
    await flush();
    assert.deepEqual(stages, ["write", "file-sync"]);
    assert.equal(late.writer.report().acknowledgedRows, 0);
  }));

test("native_throws_lifecycle_and_uncommitted_terminal_never_infer_peer_success", () =>
  withClock(async (clock) => {
    for (const nativeEvent of ["aborted", "error", "goaway", "close"]) {
      const f = await fixture();
      await f.bridge.open();
      (nativeEvent === "goaway" ? f.session : f.session.stream).emit(
        nativeEvent,
        new Error("native"),
      );
      const report = await f.bridge.done();
      assert.equal(report.provenance.peerTerminal, null);
      assert.equal(report.verdict, "uncertain");
      assert.equal(f.session.destroyCalls, 1);
    }
    for (const throwing of ["request", "cancel", "destroy"]) {
      const session = new Session();
      if (throwing === "request")
        session.onRequest = () => {
          throw Error("request");
        };
      if (throwing === "cancel")
        session.stream.onCancel = () => {
          throw Error("cancel");
        };
      if (throwing === "destroy")
        session.onDestroy = () => {
          throw Error("destroy");
        };
      const f = await fixture({ session });
      if (throwing === "request") await assert.rejects(f.bridge.open());
      else await f.bridge.open();
      const closing = f.bridge.done();
      await flush();
      await clock.advance(101);
      const report = await closing;
      assert.equal(report.verdict, "uncertain");
      assert.equal(report.provenance.peerTerminal, null);
      assert.equal(session.destroyCalls, 1);
      if (throwing !== "request") {
        assert.equal(session.stream.closeCalls, 1);
        assert.equal(report.terminationRequired, true);
        assert.ok(report.reasons.includes("native-close-unconfirmed"));
      }
    }
    const held = deferred();
    let hold = false;
    const f = await fixture({ write: () => (hold ? held.promise : Promise.resolve()) });
    await f.bridge.open();
    hold = true;
    terminal(f.session.stream);
    await flush();
    const pending = f.bridge.done();
    await clock.advance(101);
    const report = await pending;
    assert.equal(report.provenance.peerTerminal, null);
    assert.equal(report.terminationRequired, true);
    assert.equal(report.verdict, "uncertain");
    assert.ok(report.receipts.unknownEvents > 0);
    assert.ok(report.journal.unknownEntries > 0);
    const snapshot = structuredClone(report);
    held.resolve();
    await flush();
    assert.deepEqual(report, snapshot);
    const suffix = await fixture();
    await suffix.bridge.open();
    terminal(suffix.session.stream);
    suffix.session.stream.emit("data", Buffer.alloc(0));
    const contradictory = await suffix.bridge.done();
    assert.equal(contradictory.provenance.peerTerminal.status, 0);
    assert.equal(contradictory.provenance.verdict, "uncertain");
    assert.ok(contradictory.provenance.reasons.includes("data-after-terminal"));
  }));

test("clock_drains_microtask_registered_due_timers_without_extending_time", () =>
  withClock(async (clock) => {
    const observed = [];
    const cleared = setTimeout(() => observed.push("cleared"), 0);
    clearTimeout(cleared);
    setTimeout(() => observed.push("future"), 11);
    Promise.resolve().then(() => setTimeout(() => observed.push("due"), 0));
    await clock.advance(10);
    assert.deepEqual(observed, ["due"]);
    assert.equal(clock.now(), 10);
    assert.equal([...clock.timers.values()].filter((timer) => timer.at <= 10).length, 0);
    await clock.advance(1);
    assert.equal(clock.now(), 11);
    assert.deepEqual(observed, ["due", "future"]);
    let calls = 0;
    const repeat = () => {
      calls++;
      setTimeout(repeat, 0);
    };
    Promise.resolve().then(() => setTimeout(repeat, 0));
    await assert.rejects(clock.advance(0), /did not converge/);
    assert.ok(calls > 0 && calls <= 32);
    assert.equal(clock.now(), 11);
  }));

test("generated_fault_schedules_reach_all_groups_against_independent_effect_facts", async () => {
  let seed = 0x6a09e667;
  const random = (n) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const cases = [
    "pre-WAL-hold",
    "post-WAL-revoke",
    "inline-event",
    "throw-after-event",
    "false-write",
    "raw-present-refusal",
    "raw-absent-refusal",
    "observer-await-write",
    "deadline-held-writer",
    "peer-before-local",
    "peer-after-local",
    "stop-row-reserve",
    "unconfirmed-closure",
    "suffix-contradiction",
  ];
  const reached = new Set(),
    groups = new Set(),
    innerVerdicts = new Set();
  for (let repetition = 0; repetition < 3; repetition++) {
    const order = cases
      .map((name) => ({ name, rank: random(1000000) }))
      .toSorted((a, b) => a.rank - b.rank);
    for (const { name } of order)
      await withClock(async (clock) => {
        const payload = Buffer.alloc(1 + random(8), 65 + random(20));
        const held = deferred(),
          stored = [];
        let holding = false,
          live = true,
          owner,
          expectedRequests = 1,
          expectedWrites = 0,
          expectedEnd = 0,
          peerBeforeStop = false,
          peerAfterStop = false,
          terminalCommitted = false,
          taintedTerminal = false,
          expectedFrames = 0;
        const f = await fixture({
          credential: "abcdefghTOKEN",
          limits: name === "stop-row-reserve" ? { ...limits, maxChunks: repetition + 1 } : limits,
          liveCheck: () => live,
          write: (row) => {
            stored.push(structuredClone(row));
            const record = decoded([row])[0];
            if (
              name === "post-WAL-revoke" &&
              record.type === "action" &&
              record.intent.state === "before-send"
            )
              live = false;
            return holding ? held.promise : Promise.resolve();
          },
          onFrame: async () => {
            expectedFrames++;
            if (name === "observer-await-write") await owner.write(payload);
          },
        });
        owner = f.bridge;
        if (name === "pre-WAL-hold") {
          groups.add(1);
          holding = true;
          const opening = owner.open();
          await flush();
          assert.equal(f.session.requests.length, 0);
          holding = false;
          held.resolve();
          await opening;
        } else if (name === "post-WAL-revoke") {
          groups.add(1);
          expectedRequests = 0;
          await assert.rejects(owner.open());
        } else await owner.open();
        if (["inline-event", "throw-after-event"].includes(name)) {
          groups.add(4);
          expectedWrites = 1;
          peerBeforeStop = true;
          terminalCommitted = true;
          f.session.stream.onWrite = () => {
            terminal(f.session.stream);
            if (name === "throw-after-event") throw Error("after callback");
          };
          if (name === "throw-after-event") await assert.rejects(owner.write(payload));
          else await owner.write(payload);
        } else if (name === "false-write") {
          groups.add(9);
          f.session.stream.writeResult = false;
          await owner.write(payload);
          expectedWrites = 1;
        } else if (name.startsWith("raw-")) {
          groups.add(8);
          f.session.stream.emit(
            "data",
            name === "raw-present-refusal" ? Buffer.from([1, 0, 0, 0, 0]) : Buffer.from("abcdefgh"),
          );
        } else if (name === "observer-await-write") {
          groups.add(7);
          f.session.stream.emit("data", frame(payload));
          for (let i = 0; i < 20; i++) await flush();
          expectedWrites = 1;
        } else if (name === "deadline-held-writer") {
          groups.add(2);
          groups.add(3);
          groups.add(9);
          holding = true;
          const action = owner.write(payload);
          action.catch(() => {});
          await flush();
        } else if (name === "peer-before-local") {
          groups.add(5);
          terminal(f.session.stream);
          peerBeforeStop = true;
          terminalCommitted = true;
          if (random(2)) {
            await owner.halfClose();
            expectedEnd = 1;
          }
          await owner.cancel();
        } else if (name === "peer-after-local") {
          groups.add(5);
          terminalCommitted = true;
          peerAfterStop = true;
          f.session.stream.onCancel = () => terminal(f.session.stream);
          await owner.cancel();
        } else if (name === "unconfirmed-closure") {
          groups.add(3);
          groups.add(9);
          f.session.stream.acks = false;
          f.session.acks = false;
        } else if (name === "stop-row-reserve") {
          groups.add(6);
          for (let count = 0; count <= repetition; count++) {
            f.session.stream.emit("data", Buffer.alloc(0));
            await flush();
            assert.equal(f.session.destroyCalls, 0);
          }
          f.session.stream.emit("data", Buffer.alloc(0));
          assert.equal(f.session.destroyCalls, 1);
          owner.stopNow("abort");
          owner.stopNow("deadline");
        } else if (name === "suffix-contradiction") {
          groups.add(8);
          terminal(f.session.stream);
          terminalCommitted = true;
          peerBeforeStop = true;
          f.session.stream.emit("data", Buffer.alloc(0));
          taintedTerminal = true;
        }
        const closing = owner.done();
        await flush();
        if (["deadline-held-writer", "unconfirmed-closure"].includes(name))
          await clock.advance(101);
        const report = await closing;
        const expectedInner =
          taintedTerminal || peerAfterStop
            ? "uncertain"
            : terminalCommitted && peerBeforeStop
              ? "peer-terminal"
              : "local-stop";
        assert.equal(report.provenance.verdict, expectedInner, name);
        innerVerdicts.add(report.provenance.verdict);
        assert.equal(
          report.provenance.peerTerminal?.status ?? null,
          terminalCommitted ? 0 : null,
          name,
        );
        assert.equal(f.session.requests.length, expectedRequests, name);
        assert.equal(f.session.stream.writes.length, expectedWrites, name);
        assert.equal(f.session.stream.endCalls, expectedEnd, name);
        assert.equal(f.session.destroyCalls, 1, name);
        assert.equal(f.session.stream.closeCalls, expectedRequests, name);
        assert.equal(report.verdict, "uncertain", name);
        assert.equal(
          new Set(report.chronology.map((row) => row.seq)).size,
          report.chronology.length,
          name,
        );
        assert.ok(report.chronology.length <= limits.maxChronologyRows, name);
        assert.ok(report.bindings.length <= limits.maxEvents, name);
        assert.equal(expectedFrames, name === "observer-await-write" ? 1 : 0, name);
        for (const binding of report.bindings.filter((b) => b.state === "committed")) {
          const record = decoded(stored).find((_r, i) => stored[i].index === binding.journalIndex);
          assert.equal(record.nativeSeq, binding.seq, name);
          assert.equal(record.receipt.index, binding.receiptIndex, name);
          assert.equal(record.receipt.kind, binding.kind, name);
        }
        if (name === "stop-row-reserve") {
          const reserved = decoded(stored).filter(
            (r) =>
              r.type === "stop" || ["native-close-ack", "local-stop-return"].includes(r.row?.event),
          );
          assert.equal(reserved.length, 4);
        }
        if (name.startsWith("raw-"))
          assert.equal(
            report.bindings[0].state,
            name === "raw-present-refusal" ? "committed" : "raw-absent",
          );
        const snapshot = structuredClone(report);
        holding = false;
        held.resolve();
        await flush();
        assert.deepEqual(report, snapshot, name);
        reached.add(name);
      });
  }
  assert.deepEqual([...reached].toSorted(), [...cases].toSorted());
  assert.deepEqual([...groups].toSorted(), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.deepEqual([...innerVerdicts].toSorted(), ["local-stop", "peer-terminal", "uncertain"]);
});

test("raw_visibility_waits_for_its_bound_durable_ticket_and_stays_closed_after_deadline", () =>
  withClock(async (clock) => {
    for (const expire of [false, true]) {
      const held = deferred();
      let holding = false,
        visible = 0;
      const f = await fixture({
        write: () => (holding ? held.promise : Promise.resolve()),
        onFrame: () => {
          visible++;
        },
      });
      await f.bridge.open();
      holding = true;
      f.session.stream.emit("data", frame(Buffer.from("a")));
      await flush();
      assert.equal(visible, 0);
      let report;
      if (expire) {
        const pending = f.bridge.done();
        await clock.advance(101);
        report = await pending;
        assert.equal(report.verdict, "uncertain");
        assert.equal(report.terminationRequired, true);
        assert.equal(visible, 0);
      }
      holding = false;
      held.resolve();
      for (let pass = 0; pass < 10; pass++) await flush();
      assert.equal(visible, expire ? 0 : 1);
      if (expire) {
        const copy = structuredClone(report);
        await flush();
        assert.deepEqual(report, copy);
      } else {
        report = await f.bridge.done();
        assert.equal(report.bindings.find((binding) => binding.kind === "data").state, "committed");
      }
    }
  }));

test("lifecycle_callback_kind_and_native_sequence_bind_to_the_same_durable_receipt", () =>
  withClock(async () => {
    for (const [native, receipt] of [
      ["error", "error"],
      ["aborted", "reset"],
      ["goaway", "goaway"],
      ["end", "end"],
    ]) {
      const f = await fixture();
      await f.bridge.open();
      (native === "goaway" ? f.session : f.session.stream).emit(native, new Error("native"));
      const report = await f.bridge.done();
      const binding = report.bindings.find((item) => item.kind === receipt);
      assert.equal(binding.state, "committed");
      const record = decoded(f.rows).find(
        (_item, index) => f.rows[index].index === binding.journalIndex,
      );
      assert.equal(record.nativeSeq, binding.seq);
      assert.equal(record.receipt.kind, receipt);
      assert.equal(record.receipt.index, binding.receiptIndex);
    }
  }));

test("writer_lifetime_caps_stay_fixed_to_the_admitted_constructor_values", () =>
  withClock(async () => {
    const { createOwnedJournalWriter } = await exports();
    const body = Buffer.from("x");
    const row = {
      index: 0,
      bodyBase64: body.toString("base64"),
      bodyBytes: 1,
      sha256: createHash("sha256").update(body).digest("hex"),
    };
    const admitted = { maxWriterRows: 1, maxWriterRecordBytes: 1024, maxWriterBytes: 2048 };
    const effects = [];
    const writer = createOwnedJournalWriter({
      deadlineAt: 100,
      limits: admitted,
      fileHandle: {
        async write(bytes) {
          effects.push("write");
          return { bytesWritten: bytes.length };
        },
        async sync() {
          effects.push("file-sync");
        },
      },
      directoryHandle: {
        async sync() {
          effects.push("directory-sync");
        },
      },
    });
    admitted.maxWriterRows = Infinity;
    admitted.maxWriterRecordBytes = Infinity;
    admitted.maxWriterBytes = Infinity;
    await writer.write(row);
    await assert.rejects(writer.write({ ...row, index: 1 }));
    assert.deepEqual(effects, ["write", "file-sync", "directory-sync"]);
    assert.equal(writer.report().acknowledgedRows, 1);
  }));
