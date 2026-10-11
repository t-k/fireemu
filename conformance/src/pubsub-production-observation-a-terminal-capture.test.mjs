import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { openStream } from "./pubsub-observation/stream.mjs";
const details =
  "A service error has occurred. Please retry your request. If the error persists, please report it. [code=e8c0]";
const opener = () => ({
  subscription: "projects/fireemu-oracle-idp/subscriptions/feabcdef123456-s10-sub",
  streamAckDeadlineSeconds: 0,
  maxOutstandingMessages: "1",
  maxOutstandingBytes: "1024",
});
async function fixture(mode = "natural") {
  let clockOffset = 0;
  const rpc = new EventEmitter(),
    events = [];
  rpc.write = () => true;
  rpc.end = () => {};
  rpc.cancel = () => {};
  const opening = opener();
  if (mode === "other-deadline") opening.streamAckDeadlineSeconds = 10;
  if (mode === "foreign-subscription")
    opening.subscription = "projects/fireemu-oracle-idp/subscriptions/foreign";
  if (mode === "wrong-credits") opening.maxOutstandingMessages = "2";
  if (mode === "extra-opening-field") opening.ackIds = ["unrelated"];
  const stream = await openStream({
    meter: {
      start() {},
      frame(direction) {
        if (direction === "in" && mode === "frame-refused") throw Error("frame cap");
      },
      clock: () => performance.now() + clockOffset,
      remaining: () => (mode === "clipped-window" ? 50000 : 140000),
    },
    client: { makeBidiStreamRequest: () => rpc },
    credential: async () => "offline-dummy",
    journal: {
      write: (x) => {
        events.push(x);
        if (mode === "persistence-failure" && x.event === "stream-status")
          throw Error("status persistence failure");
      },
      frame: (_raw, x) => events.push(x),
    },
    runId: mode === "wrong-runId" ? "fedcba654321" : "abcdef123456",
    cellId: mode === "other-cell" ? "S11" : "S10",
    opener: opening,
  });
  const metadata = new grpc.Metadata();
  if (mode === "metadata-overflow") metadata.set("oversized", "x".repeat(65536));
  const error = {
      code: 13,
      details: mode === "other-INTERNAL" ? "different internal failure" : details,
    },
    status = {
      code: mode === "different-status" ? 14 : 13,
      details:
        mode === "different-details"
          ? "different service error"
          : mode === "other-INTERNAL"
            ? "different internal failure"
            : details,
      metadata: new grpc.Metadata(),
    };
  function emit() {
    if (mode === "local-window-cancel") {
      error.code = 1;
      status.code = 1;
      stream.cancel("window-end");
    }
    if (mode === "expired-window") clockOffset = 90001;
    if (mode === "extra-write") stream.write({});
    if (mode === "half-close") stream.end();
    if (mode !== "missing-metadata") rpc.emit("metadata", metadata);
    if (["data-before-terminal", "frame-refused"].includes(mode))
      rpc.emit(
        "data",
        Buffer.from(protos.google.pubsub.v1.StreamingPullResponse.encode({}).finish()),
      );
    if (mode === "cancelled") stream.cancel("source-signal");
    if (mode !== "missing-error") rpc.emit("error", error);
    if (mode === "duplicate-error") rpc.emit("error", error);
    if (mode === "end-before-status") rpc.emit("end");
    if (mode !== "missing-status") rpc.emit("status", status);
    if (mode === "duplicate-status") rpc.emit("status", status);
    if (mode !== "missing-end") rpc.emit("end");
  }
  return { stream, rpc, events, emit, error, status, metadata };
}
test("S10 candidate waits within the absolute window for exact zero natural error status and end", async () => {
  const f = await fixture();
  setImmediate(() => {
    f.rpc.emit("metadata", f.metadata);
    f.rpc.emit("error", f.error);
    setImmediate(() => {
      f.rpc.emit("status", f.status);
      setImmediate(() => f.rpc.emit("end"));
    });
  });
  try {
    assert.equal(await f.stream.next(100), null);
    const state = f.stream.state();
    assert.equal(state.inboundEnded, true, "candidate must capture natural end before snapshot");
    assert.equal(
      state.incomplete,
      false,
      "candidate distinguishes complete capture from source loss",
    );
    assert.equal(state.terminal.code, 13);
    assert.equal(state.windowExpired, false);
    assert.equal(state.received, 0);
    assert.equal(
      f.events.some((e) => e.event === "stream-cancel"),
      false,
    );
  } finally {
    await f.stream.disposeWithDiagnostics();
    f.stream.dispose();
  }
});
for (const mode of [
  "local-window-cancel",
  "wrong-runId",
  "missing-error",
  "duplicate-error",
  "duplicate-status",
  "expired-window",
  "end-before-status",
  "other-deadline",
  "other-INTERNAL",
  "foreign-subscription",
  "wrong-credits",
  "extra-write",
  "half-close",
  "other-cell",
  "extra-opening-field",
  "clipped-window",
  "metadata-overflow",
  "missing-metadata",
  "different-status",
  "different-details",
  "missing-status",
  "missing-end",
  "data-before-terminal",
  "frame-refused",
  "cancelled",
]) {
  test(`S10 candidate preserves incomplete for ${mode}`, async () => {
    const f = await fixture(mode);
    try {
      f.emit();
      assert.equal(f.stream.state().incomplete, true);
    } finally {
      await f.stream.disposeWithDiagnostics();
      f.stream.dispose();
    }
  });
}

test("S10 known pending terminal still requires natural end inside the original caller wait", async () => {
  const f = await fixture();
  try {
    f.rpc.emit("metadata", f.metadata);
    f.rpc.emit("error", f.error);
    f.rpc.emit("status", f.status);
    const begun = performance.now();
    assert.equal(await f.stream.next(5), null);
    assert.ok(performance.now() - begun < 100, "missing end must not extend the caller bound");
    assert.equal(f.stream.state().incomplete, true);
  } finally {
    await f.stream.disposeWithDiagnostics();
    f.stream.dispose();
  }
});
const { runCell } = await import("./pubsub-observation/scenarios.mjs");
const { makePlan } = await import("./pubsub-observation/plan.mjs");
const { createMeter } = await import("./pubsub-observation/meter.mjs");
const { createLedger } = await import("./pubsub-production/ledger.mjs");
for (const known of [true, false])
  test(`S10 real scenario preserves known capture=${known} and exact raw terminal`, async () => {
    const plan = makePlan(),
      cell = plan.cells.find((c) => c.id === "S10"),
      meter = createMeter({ plan });
    meter.enter(cell);
    const resources = new Map(),
      calls = [],
      events = [];
    const journal = {
      write: (e) => events.push(e),
      frame: (_raw, e) => events.push(e),
      recovery() {},
    };
    const wire = {
      async call(call) {
        calls.push(call);
        meter.start(call.category, call.transport);
        const name = call.request.name ?? call.request.topic;
        if (call.method.startsWith("Create")) {
          resources.set(name, call.request);
          return { ok: true, code: "OK", unknown: false, body: { ...call.request } };
        }
        if (call.method.startsWith("Delete")) {
          resources.delete(name);
          return { ok: true, code: "OK", unknown: false, body: {} };
        }
        if (call.method.startsWith("Get"))
          return resources.has(name)
            ? { ok: true, code: "OK", unknown: false, body: resources.get(name) }
            : {
                ok: false,
                code: "NOT_FOUND",
                status: 404,
                unknown: false,
                body: { error: { status: "NOT_FOUND" } },
              };
        if (call.method === "Publish")
          return {
            ok: true,
            code: "OK",
            unknown: false,
            body: { messageIds: ["owned-publication"] },
          };
        throw Error("unlisted fixture method");
      },
      async open(value) {
        const rpc = new EventEmitter();
        rpc.write = () => true;
        rpc.cancel = () => {};
        rpc.end = () => {};
        const stream = await openStream({
          ...value,
          meter,
          journal,
          credential: async () => "offline-dummy",
          client: { makeBidiStreamRequest: () => rpc },
        });
        setImmediate(() => {
          rpc.emit("metadata", new grpc.Metadata());
          rpc.emit("error", { code: 13, details: known ? details : "different internal failure" });
          setImmediate(() => {
            rpc.emit("status", {
              code: 13,
              details: known ? details : "different internal failure",
              metadata: new grpc.Metadata(),
            });
            setImmediate(() => rpc.emit("end"));
          });
        });
        return stream;
      },
    };
    const result = await runCell({
      cell,
      meter,
      wire,
      ledger: createLedger(),
      runId: "abcdef123456",
      journal,
      sleep: async () => {},
    });
    assert.equal(result.complete, known);
    assert.equal(result.cleanupClosed, true);
    assert.equal(calls.filter((c) => c.method.startsWith("Delete")).length, 2);
    const terminal = events.find((e) => e.event === "stream-error");
    assert.equal(terminal.code, 13);
    assert.equal(terminal.details, known ? details : "different internal failure");
    if (known) {
      assert.equal(events.find((e) => e.event === "stream-status").details, details);
      assert.ok(events.some((e) => e.event === "stream-inbound-end"));
    }
    assert.equal(
      events.find((e) => e.event === "stream-case-observation").state.incomplete,
      !known,
    );
  });

test("S10 status persistence failure prevents complete capture even if end later arrives", async () => {
  const f = await fixture("persistence-failure");
  try {
    assert.throws(() => f.emit(), /status persistence failure/);
    f.rpc.emit("end");
    assert.equal(f.stream.state().incomplete, true);
  } finally {
    await f.stream.disposeWithDiagnostics();
    f.stream.dispose();
  }
});
