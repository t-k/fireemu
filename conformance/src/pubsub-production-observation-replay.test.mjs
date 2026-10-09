import test from "node:test";
import assert from "node:assert/strict";
import { protos } from "@google-cloud/pubsub";
import { createHash } from "node:crypto";
import { compareExecutedObservation } from "./pubsub-observation/compare-core.mjs";
import { createBindings } from "./pubsub-production/stream-dlq-compare-core.mjs";
import {
  rewriteNativeFrame,
  matchNativeReceive,
  createActionClock,
} from "./pubsub-observation/replay-native.mjs";
import { validateReplaySource } from "./pubsub-observation/replay.mjs";
import { fixture, generatedTimeProof } from "./pubsub-production-observation-compare.test.mjs";

const message = (id, ack, data = "bWFya2Vy") => ({
  receivedMessages: [{ ackId: ack, message: { messageId: id, data } }],
});
test("native ACK and deadline selectors require publication then actual receive", () => {
  for (let i = 0; i < 64; i++) {
    const b = createBindings(),
      source = `source-${i}`,
      local = `local-${i}`;
    const frame = { modifyDeadlineAckIds: [`ack-${i}`], modifyDeadlineSeconds: [0] };
    assert.throws(() => rewriteNativeFrame(frame, b), /binding/);
    b.linkPublish(
      { messages: [{ data: "bWFya2Vy" }] },
      { messageIds: [source] },
      { messageIds: [local] },
    );
    matchNativeReceive(message(source, `ack-${i}`), message(local, `local-ack-${i}`), b);
    assert.deepEqual(rewriteNativeFrame(frame, b), {
      modifyDeadlineAckIds: [`local-ack-${i}`],
      modifyDeadlineSeconds: [0],
    });
    assert.deepEqual(rewriteNativeFrame({ ackIds: [`ack-${i}`] }, b), {
      ackIds: [`local-ack-${i}`],
    });
  }
});
test("native receive refuses foreign data, duplicate delivery and unbound publication", () => {
  for (const mutate of [
    (x) => (x.receivedMessages[0].message.data = "Zm9yZWlnbg=="),
    (x) => x.receivedMessages.push(x.receivedMessages[0]),
    (x) => (x.receivedMessages[0].message.messageId = "foreign"),
  ]) {
    const b = createBindings();
    b.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
    const actual = message("local", "ack-local");
    mutate(actual);
    assert.throws(
      () => matchNativeReceive(message("source", "ack-source"), actual, b),
      /receive|binding/,
    );
  }
});
test("only the declared invalid ACK is preserved without a binding", () => {
  const b = createBindings();
  assert.deepEqual(
    rewriteNativeFrame(
      { ackIds: ["invalid-ack-for-stream-observation"] },
      b,
      "invalid-ack-for-stream-observation",
    ),
    { ackIds: ["invalid-ack-for-stream-observation"] },
  );
  assert.throws(
    () =>
      rewriteNativeFrame(
        { modifyDeadlineAckIds: ["unknown"] },
        b,
        "invalid-ack-for-stream-observation",
      ),
    /binding/,
  );
});
test("action clock uses explicit dispatch instants and independently measured elapsed time", async () => {
  let now = 10;
  const calls = [],
    sleeps = [];
  const clock = createActionClock({
    advance: async (x) => calls.push(x),
    now: () => now,
    wait: async (ms) => {
      sleeps.push(ms);
      now += ms;
    },
  });
  await clock.dispatch({ n: 2, at: new Date(2000).toISOString() });
  clock.open("S01");
  await clock.native({ cellId: "S01", elapsedMs: 5000, at: new Date(7000).toISOString(), n: 3 });
  assert.deepEqual(sleeps, [5000]);
  assert.equal(calls[1].instant, new Date(7000).toISOString());
  await assert.rejects(clock.dispatch({ at: new Date(6000).toISOString() }), /regress/);
  await assert.rejects(
    clock.native({ cellId: "S02", elapsedMs: 0, at: new Date(8000).toISOString() }),
    /open/,
  );
});
async function postWindowFixture(t, alter = () => {}) {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  let now = 0;
  const waits = [],
    actions = [],
    advances = [];
  const windowEnd = {
    n: 42,
    cellId: "S13",
    event: "stream-observation-window-end",
    elapsedMs: 89999.93512499999,
    at: new Date(90999).toISOString(),
  };
  const cancel = {
    n: 43,
    cellId: "S13",
    event: "stream-cancel",
    reason: "window-end",
    elapsedMs: 90004.78279200001,
    at: new Date(91004).toISOString(),
  };
  const source = { id: "S13", events: [windowEnd, structuredClone(cancel)] };
  alter({ source, windowEnd, cancel });
  const replay = createNativeReplay({
    cells: [{ id: "S13", group: "G4", variant: "opening-deadline-601" }],
    sourceCells: [source],
    bindings: createBindings(),
    clock: createActionClock({
      now: () => now,
      wait: async (ms) => {
        waits.push(ms);
        now += ms;
      },
      advance: async (row) => advances.push(row),
    }),
    wire: {
      open: async () => ({
        cancel: (reason) => actions.push(reason),
        end: () => actions.push("write-end"),
        state: () => ({ incomplete: true, terminal: null, inboundEnded: false }),
        dispose() {},
      }),
    },
  });
  t.after(() => replay.close());
  await replay.frame({
    n: 39,
    cellId: "S13",
    event: "stream-frame",
    direction: "out",
    elapsedMs: 0,
    at: new Date(1000).toISOString(),
    body: { subscription: "owned", streamAckDeadlineSeconds: 601 },
  });
  return { replay, cancel, source, waits, actions, advances };
}

test("source-bound window cancellation preserves the recorded post-window elapsed time", async (t) => {
  for (const [endMs, cancelMs] of [
    [89999.93512499999, 90004.78279200001],
    [90001.09804099999, 90010.44237500001],
  ]) {
    const f = await postWindowFixture(t, ({ source, windowEnd, cancel }) => {
      windowEnd.elapsedMs = endMs;
      windowEnd.at = new Date(1000 + endMs).toISOString();
      cancel.elapsedMs = cancelMs;
      cancel.at = new Date(1000 + cancelMs).toISOString();
      source.events[1] = structuredClone(cancel);
    });
    const original = structuredClone(f.cancel);
    const originalEvents = structuredClone(f.source.events);
    await f.replay.action(f.cancel);
    assert.deepEqual(f.waits, [cancelMs]);
    assert.deepEqual(f.actions, ["window-end"]);
    assert.deepEqual(f.cancel, original);
    assert.deepEqual(f.source.events, originalEvents);
    const proof = f.replay.witnesses.get("S13");
    assert.equal(proof.actions[0].elapsedMs, original.elapsedMs);
    assert.equal(f.advances.at(-1).instant, original.at);
    assert.equal(proof.completed, false);
    assert.equal(proof.semanticsVerified, false);
    await assert.rejects(
      f.replay.action({
        n: 49,
        cellId: "S13",
        event: "stream-case-observation",
        at: new Date(91024).toISOString(),
        state: { terminal: { code: 1 }, inboundEnded: true },
      }),
      /terminal witness/,
    );
    assert.equal(proof.completed, false);
  }
});

test("post-window timing requires the exact source cancel and its preceding window witness", async (t) => {
  for (const alter of [
    ({ source }) => source.events.shift(),
    ({ source }) => source.events.pop(),
    ({ source }) => source.events.push(structuredClone(source.events[0])),
    ({ windowEnd }) => (windowEnd.cellId = "foreign"),
    ({ windowEnd }) => (windowEnd.n = 44),
    ({ windowEnd }) => (windowEnd.elapsedMs = NaN),
    ({ windowEnd }) => (windowEnd.elapsedMs = Infinity),
    ({ windowEnd }) => (windowEnd.elapsedMs = -1),
    ({ windowEnd, cancel }) => (windowEnd.elapsedMs = cancel.elapsedMs + 1),
    ({ windowEnd, cancel }) => (windowEnd.at = new Date(Date.parse(cancel.at) + 1).toISOString()),
    ({ cancel, source }) => {
      cancel.reason = "dispose";
      source.events[1] = structuredClone(cancel);
    },
    ({ cancel, source }) => {
      cancel.event = "stream-write-end";
      source.events[1] = structuredClone(cancel);
    },
  ]) {
    const f = await postWindowFixture(t, alter);
    await assert.rejects(f.replay.action(f.cancel), /native elapsed bound/);
    assert.deepEqual(f.waits, []);
    assert.deepEqual(f.actions, []);
  }
});

test("normal native frames and actions retain finite window and cleanup ceilings", async (t) => {
  for (const elapsedMs of [-1, NaN, Infinity, 130000.001]) {
    const f = await postWindowFixture(t, ({ source, cancel }) => {
      cancel.elapsedMs = elapsedMs;
      source.events[1] = structuredClone(cancel);
    });
    await assert.rejects(f.replay.action(f.cancel), /native elapsed bound/);
    assert.deepEqual(f.waits, []);
  }
  for (const elapsedMs of [90000.001, NaN, Infinity, -1]) {
    for (const direction of ["out", "in"]) {
      const f = await postWindowFixture(t);
      await assert.rejects(
        f.replay.frame({
          n: 41,
          cellId: "S13",
          direction,
          at: new Date(92000).toISOString(),
          elapsedMs,
          body: {},
        }),
        /native elapsed bound/,
      );
    }
  }
  for (const event of ["stream-write-end", "stream-case-observation"]) {
    const f = await postWindowFixture(t);
    await assert.rejects(f.replay.action({ ...f.cancel, event }), /native elapsed bound/);
  }
  const boundary = await postWindowFixture(t, ({ source, cancel }) => {
    cancel.elapsedMs = 130000;
    cancel.at = new Date(131000).toISOString();
    source.events[1] = structuredClone(cancel);
  });
  await boundary.replay.action(boundary.cancel);
  assert.deepEqual(boundary.waits, [130000]);
});

test("source binding and raw frame proof fail before any local action", () => {
  const f = fixture();
  assert.doesNotThrow(() => validateReplaySource(f));
  f.rows[1].at = "invalid";
  assert.throws(() => validateReplaySource(f), /chronology/);
  const raw = fixture();
  raw.rows.splice(3, 0, {
    event: "stream-frame",
    direction: "out",
    cellId: "S01",
    body: {},
    at: new Date(3500).toISOString(),
  });
  raw.rows.forEach((r, i) => (r.n = i + 1));
  assert.throws(() => validateReplaySource(raw), /raw frame/);
});
test("release runtime pins reject missing genuine build fields and non-loopback targets", async () => {
  const { validateRuntime } = await import("./pubsub-production/stream-dlq-compare.mjs");
  const pin = {
    profile: "release",
    rustcWrapper: "",
    path: "/fixture/release/fireemu",
    head: "a".repeat(40),
    sha256: "b".repeat(64),
    command: ["cargo", "build", "--release"],
  };
  const env = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:4321/v1/",
    FIREEMU_CONTROL_TOKEN: "synthetic-control",
  };
  assert.doesNotThrow(() => validateRuntime(pin, env));
  for (const update of [
    { profile: "dev" },
    { rustcWrapper: "sccache" },
    { command: ["cargo", "build"] },
    { path: "/fixture/fireemu" },
    { sha256: "wrong" },
  ])
    assert.throws(() => validateRuntime({ ...pin, ...update }, env), /release/);
  assert.throws(
    () => validateRuntime(pin, { ...env, PUBSUB_EMULATOR_HOST: "pubsub.googleapis.com:443" }),
    /loopback/,
  );
});
test("actual unary replay closes transports on a failed clock action", async () => {
  const { replayA } = await import("./pubsub-observation/replay.mjs");
  const f = fixture(),
    closed = [];
  const pin = {
    profile: "release",
    rustcWrapper: "",
    path: "/fixture/release/fireemu",
    head: "a".repeat(40),
    sha256: "b".repeat(64),
    command: ["cargo", "build", "--release"],
  };
  const env = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:4321/v1/",
    FIREEMU_CONTROL_TOKEN: "synthetic-control",
  };
  await assert.rejects(
    replayA(f, env, pin, {
      wireFactory: () => ({ close: () => closed.push("closed") }),
      advance: async () => {
        throw new Error("clock refused");
      },
    }),
    /clock refused/,
  );
  assert.deepEqual(closed, ["closed"]);
});
test("large A payload reconstruction must reproduce the exact omitted bytes", async () => {
  const { restoreRequest } = await import("./pubsub-observation/replay.mjs");
  const { boundaryPayload } = await import("./pubsub-observation/payload.mjs");
  const { sanitize } = await import("./pubsub-production/capture.mjs");
  const topic = "projects/fireemu-oracle-idp/topics/fe012345abcdef-r6-topic";
  const messages = boundaryPayload({
    topic,
    transport: "rest",
    kind: "request",
    target: 8192,
  }).messages;
  const row = { method: "Publish", transport: "rest", request: sanitize({ topic, messages }) };
  assert.deepEqual(restoreRequest(row, { variant: "request-8192" }).messages, messages);
  row.request.messages[0].data.omitted.sha256 = "0".repeat(64);
  assert.throws(() => restoreRequest(row, { variant: "request-8192" }), /hash proof/);
});

test("finite native connector executes receive, ACK, half-close and measured observation in source order", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  const { makePlan } = await import("./pubsub-observation/plan.mjs");
  let now = 0;
  const actions = [],
    bindings = createBindings();
  bindings.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
  const stream = {
    write: (body) => actions.push(["write", body]),
    next: async () => message("local", "local-ack"),
    end: () => actions.push(["end"]),
    cancel() {},
    state: () => ({ incomplete: false, terminal: null }),
    dispose: () => actions.push(["dispose"]),
  };
  const clock = createActionClock({
    now: () => now,
    wait: async (ms) => (now += ms),
    advance: async () => {},
  });
  const replay = createNativeReplay({
    wire: {
      open: async ({ opener }) => {
        actions.push(["open", opener]);
        return stream;
      },
    },
    bindings,
    clock,
    cells: makePlan().cells,
  });
  const row = (n, elapsedMs, direction, body) => ({
    n,
    cellId: "S03",
    elapsedMs,
    at: new Date(1000 + elapsedMs).toISOString(),
    direction,
    body,
  });
  await assert.rejects(replay.frame(row(1, 0, "in", message("source", "source-ack"))), /opener/);
  await replay.frame(row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }));
  await replay.frame(row(2, 1000, "in", message("source", "source-ack")));
  await replay.frame(row(3, 2000, "out", { ackIds: ["source-ack"] }));
  await replay.action({ ...row(4, 3000), event: "stream-write-end" });
  await replay.action({
    ...row(5, 4000),
    event: "stream-case-observation",
    state: { incomplete: false, terminal: null },
  });
  replay.closeCell("S03");
  assert.deepEqual(
    actions.map((a) => a[0]),
    ["open", "write", "end", "dispose"],
  );
  assert.deepEqual(actions[1][1], { ackIds: ["local-ack"] });
  assert.equal(replay.witnesses.get("S03").completed, true);
  assert.deepEqual(replay.witnesses.get("S03").sourceFrames, [1, 2, 3]);
});

test("local replay uses the declared credential-free strict transport without changing original metadata", async () => {
  const { anonymousLocalMetadata, createReplayClient } =
    await import("./pubsub-observation/replay-native.mjs");
  const grpc = (await import("@grpc/grpc-js")).default;
  const original = new grpc.Metadata();
  original.add("authorization", "Bearer synthetic-local-only");
  original.add("x-goog-user-project", "fixture-project");
  const actual = anonymousLocalMetadata(original);
  assert.deepEqual(actual.get("authorization"), []);
  assert.deepEqual(actual.get("x-goog-user-project"), ["fixture-project"]);
  assert.equal(original.get("authorization").length, 1);
  assert.throws(() => createReplayClient("pubsub.googleapis.com:443"), /loopback/);
  const client = createReplayClient("127.0.0.1:1234");
  client.close();
});

test("deadline replay probes the recorded quiet interval before a later redelivery", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  const { makePlan } = await import("./pubsub-observation/plan.mjs");
  let now = 0,
    reads = 0;
  const instants = [],
    bindings = createBindings();
  bindings.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
  let replay;
  const stream = {
    write(body) {
      replay.recordFrame({ direction: "out", elapsedMs: now, body });
    },
    next: async () => {
      if (++reads === 1) return message("local", "first-local");
      now += 1000;
      return message("local", "premature-local");
    },
    state: () => ({ incomplete: false }),
    dispose() {},
  };
  const clock = createActionClock({
    now: () => now,
    wait: async (ms) => (now += ms),
    advance: async (receipt) => instants.push(receipt.instant),
  });
  replay = createNativeReplay({
    wire: { open: async () => stream },
    bindings,
    clock,
    cells: makePlan().cells,
  });
  const row = (n, elapsedMs, direction, body) => ({
    n,
    cellId: "S05",
    elapsedMs,
    at: new Date(1000 + elapsedMs).toISOString(),
    direction,
    body,
  });
  await replay.frame(row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }));
  await replay.frame(row(2, 100, "in", message("source", "first-source")));
  await replay.frame(
    row(3, 200, "out", { modifyDeadlineAckIds: ["first-source"], modifyDeadlineSeconds: [20] }),
  );
  await assert.rejects(
    replay.frame(row(4, 20200, "in", message("source", "later-source"))),
    /quiet interval/,
  );
  assert.ok(instants.includes(new Date(11200).toISOString()));
  replay.close();
});

test("actual replay keeps malformed successful UpdateSubscription body identity unknown", async () => {
  const { replayA } = await import("./pubsub-observation/replay.mjs");
  const name = "projects/fireemu-oracle-idp/subscriptions/fe012345abcdef-r3-sub";
  const pin = {
    profile: "release",
    rustcWrapper: "",
    path: "/fixture/release/fireemu",
    head: "a".repeat(40),
    sha256: "b".repeat(64),
    command: ["cargo", "build", "--release"],
  };
  const env = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:4321/v1/",
    FIREEMU_CONTROL_TOKEN: "synthetic-control",
  };
  for (const body of [{}, { name: `${name}-foreign` }]) {
    const f = fixture("UpdateSubscription", {
      ok: true,
      status: 200,
      code: "OK",
      body: { name },
      bodyBytes: 2,
    });
    f.rows[1].request = { subscription: { name }, updateMask: "labels" };
    f.rows[1].routeName = name;
    const report = await replayA(f, env, pin, {
      advance: async () => {},
      wireFactory: () => ({
        close() {},
        call: async () => ({ ok: true, status: 200, code: "OK", body, bodyBytes: 2 }),
      }),
    });
    assert.equal(report.cells.find((c) => c.id === "R3").verdict, "NOT_COMPARABLE");
  }
});

test("deadline and held-credit windows reject premature delivery and accept quiet probes with aged clocks", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  for (const variant of ["in-stream-deadline-update", "flow-control"])
    for (const premature of [false, true])
      for (const age of [0, 3600000]) {
        let now = age;
        const bindings = createBindings(),
          reads = [];
        bindings.linkPublish(
          { messages: [{}] },
          { messageIds: ["source"] },
          { messageIds: ["local"] },
        );
        const responses = [
          message("local", "first-local"),
          premature ? message("local", "early-local") : null,
          message("local", "later-local"),
        ];
        let replay;
        const stream = {
          write(body) {
            replay.recordFrame({ direction: "out", elapsedMs: now - age, body });
          },
          next: async (timeout) => {
            reads.push(timeout);
            const body = responses.shift();
            if (body) replay.recordFrame({ direction: "in", elapsedMs: now - age, body });
            return body;
          },
          dispose() {},
        };
        const clock = createActionClock({
          now: () => now,
          wait: async (ms) => (now += ms),
          advance: async () => {},
        });
        replay = createNativeReplay({
          wire: { open: async () => stream },
          bindings,
          clock,
          cells: [{ id: "S", group: "G4", variant }],
        });
        const row = (n, elapsedMs, direction, body) => ({
          n,
          cellId: "S",
          elapsedMs,
          at: new Date(1000 + elapsedMs).toISOString(),
          direction,
          body,
        });
        try {
          await replay.frame(
            row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }),
          );
          await replay.frame(row(2, 100, "in", message("source", "first-source")));
          if (variant === "in-stream-deadline-update")
            await replay.frame(
              row(3, 200, "out", {
                modifyDeadlineAckIds: ["first-source"],
                modifyDeadlineSeconds: [20],
              }),
            );
          if (variant === "flow-control" && !premature)
            await replay.frame(row(3, 15200, "out", { ackIds: ["first-source"] }));
          const later = row(4, 20200, "in", message("source", "later-source"));
          if (premature) await assert.rejects(replay.frame(later), /quiet interval/);
          else {
            await replay.frame(later);
            const probes = replay.witnesses.get("S").probes;
            assert.equal(probes.length, 1);
            assert.equal(
              probes[0].kind,
              variant === "flow-control" ? "held-credit" : "deadline-before-expiry",
            );
            assert.equal(probes[0].elapsedMs, variant === "flow-control" ? 6100 : 11200);
            assert.deepEqual(reads, [10000, 1000, 10000]);
          }
        } finally {
          replay.close();
        }
      }
});

test("deadline rejects a queued actual receive after the short probe but before expiry", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  for (const receivedAt of [12200, 20199, 20200, 20201, null]) {
    let now = 0,
      reads = 0,
      replay;
    const bindings = createBindings();
    bindings.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
    const later = message("local", "later-local");
    const stream = {
      write(body) {
        replay.recordFrame?.({ direction: "out", elapsedMs: now, body });
      },
      next: async () =>
        ++reads === 1 ? message("local", "first-local") : reads === 2 ? null : later,
      dispose() {},
    };
    const clock = createActionClock({
      now: () => now,
      wait: async (ms) => {
        const end = now + ms;
        if (receivedAt !== null && now < receivedAt && end >= receivedAt)
          replay.recordFrame?.({ direction: "in", elapsedMs: receivedAt, body: later });
        now = end;
      },
      advance: async () => {},
    });
    replay = createNativeReplay({
      wire: { open: async () => stream },
      bindings,
      clock,
      cells: [{ id: "S05", group: "G4", variant: "in-stream-deadline-update" }],
    });
    const row = (n, elapsedMs, direction, body) => ({
      n,
      cellId: "S05",
      elapsedMs,
      at: new Date(1000 + elapsedMs).toISOString(),
      direction,
      body,
    });
    try {
      await replay.frame(row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }));
      await replay.frame(row(2, 100, "in", message("source", "first-source")));
      await replay.frame(
        row(3, 200, "out", { modifyDeadlineAckIds: ["first-source"], modifyDeadlineSeconds: [20] }),
      );
      const result = replay.frame(row(4, 20201, "in", message("source", "later-source")));
      if (receivedAt === null || receivedAt < 20200)
        await assert.rejects(result, /actual receive|quiet interval/);
      else await result;
    } finally {
      replay.close();
    }
  }
});

test("temporal observation refuses a cutoff before the actual outbound deadline expires", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  for (const cutoff of [20199, 20200, 20201]) {
    let now = 0,
      replay;
    const bindings = createBindings();
    bindings.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
    let reads = 0;
    const stream = {
      write(body) {
        replay.recordFrame({ direction: "out", elapsedMs: now + 700, body });
      },
      next: async () => (++reads === 1 ? message("local", "first-local") : null),
      state: () => ({ incomplete: false, terminal: null }),
      dispose() {},
    };
    const clock = createActionClock({
      now: () => now,
      wait: async (ms) => (now += ms),
      advance: async () => {},
    });
    replay = createNativeReplay({
      wire: { open: async () => stream },
      bindings,
      clock,
      cells: [{ id: "S05", group: "G4", variant: "in-stream-deadline-update" }],
    });
    const row = (n, elapsedMs, direction, body) => ({
      n,
      cellId: "S05",
      elapsedMs,
      at: new Date(1000 + elapsedMs).toISOString(),
      direction,
      body,
    });
    try {
      await replay.frame(row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }));
      await replay.frame(row(2, 100, "in", message("source", "first-source")));
      await replay.frame(
        row(3, 200, "out", { modifyDeadlineAckIds: ["first-source"], modifyDeadlineSeconds: [20] }),
      );
      const result = replay.action({
        ...row(4, cutoff),
        event: "stream-case-observation",
        state: { incomplete: false, terminal: null },
      });
      if (cutoff < 20200) await assert.rejects(result, /ended before expiry/);
      else {
        await result;
        assert.equal(replay.witnesses.get("S05").deadlineUntilMs, 20900);
        assert.ok(replay.witnesses.get("S05").observedUntilMs >= 20900);
      }
    } finally {
      replay.close();
    }
  }
});

test("held credit rejects an actual queued delivery after its short probe and before ACK", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  let now = 0,
    reads = 0,
    replay;
  const bindings = createBindings();
  bindings.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
  const extra = message("local", "extra-local");
  const stream = {
    write(body) {
      replay.recordFrame({ direction: "out", elapsedMs: now, body });
    },
    next: async () => {
      if (++reads !== 1) return null;
      const body = message("local", "first-local");
      replay.recordFrame({ direction: "in", elapsedMs: now, body });
      return body;
    },
    dispose() {},
  };
  const clock = createActionClock({
    now: () => now,
    wait: async (ms) => {
      const end = now + ms;
      if (now < 12200 && end >= 12200)
        replay.recordFrame({ direction: "in", elapsedMs: 12200, body: extra });
      now = end;
    },
    advance: async () => {},
  });
  replay = createNativeReplay({
    wire: { open: async () => stream },
    bindings,
    clock,
    cells: [{ id: "S", group: "G4", variant: "flow-control" }],
  });
  const row = (n, elapsedMs, direction, body) => ({
    n,
    cellId: "S",
    elapsedMs,
    at: new Date(1000 + elapsedMs).toISOString(),
    direction,
    body,
  });
  try {
    await replay.frame(row(1, 0, "out", { subscription: "owned", maxOutstandingMessages: "1" }));
    await replay.frame(row(2, 100, "in", message("source", "first-source")));
    await assert.rejects(
      replay.frame(row(3, 15200, "out", { ackIds: ["first-source"] })),
      /actual receive.*quiet interval/,
    );
  } finally {
    replay.close();
  }
});

test("empty inbound frames do not shorten the measured quiet interval", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  let now = 0,
    reads = 0,
    replay;
  const bindings = createBindings();
  bindings.linkPublish({ messages: [{}] }, { messageIds: ["source"] }, { messageIds: ["local"] });
  const later = message("local", "later-local");
  const stream = {
    write(body) {
      replay.recordFrame({ direction: "out", elapsedMs: now, body });
    },
    next: async () => {
      reads++;
      if (reads === 1) return message("local", "first-local");
      if (reads === 2) {
        now += 100;
        return {};
      }
      if (reads === 3) return null;
      replay.recordFrame({ direction: "in", elapsedMs: now, body: later });
      return later;
    },
    dispose() {},
  };
  const clock = createActionClock({
    now: () => now,
    wait: async (ms) => {
      now += ms;
    },
    advance: async () => {},
  });
  replay = createNativeReplay({
    wire: { open: async () => stream },
    bindings,
    clock,
    cells: [{ id: "S", group: "G4", variant: "in-stream-deadline-update" }],
  });
  const row = (n, elapsedMs, direction, body) => ({
    n,
    cellId: "S",
    elapsedMs,
    at: new Date(1000 + elapsedMs).toISOString(),
    direction,
    body,
  });
  try {
    await replay.frame(row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }));
    await replay.frame(row(2, 100, "in", message("source", "first-source")));
    await replay.frame(
      row(3, 200, "out", { modifyDeadlineAckIds: ["first-source"], modifyDeadlineSeconds: [20] }),
    );
    await replay.frame(row(4, 20200, "in", message("source", "later-source")));
    assert.equal(replay.witnesses.get("S").probes[0].elapsedMs, 11200);
    assert.equal(reads, 4);
  } finally {
    replay.close();
  }
});

test("deadline update requires its own finite corresponding outbound receipt after a valid opener", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  for (const receipt of [undefined, null, NaN, -1, "200", "wrong-body", 200])
    for (const arrival of [20100, 20200]) {
      let now = 0,
        reads = 0,
        replay;
      const later = message("same", "later");
      const stream = {
        write(body) {
          replay.recordFrame({
            direction: "out",
            elapsedMs: receipt === "wrong-body" ? 200 : receipt,
            body: receipt === "wrong-body" ? structuredClone(body) : body,
          });
        },
        next: async () => (++reads === 1 ? message("same", "first") : reads === 2 ? null : later),
        state: () => ({ incomplete: false, terminal: null }),
        dispose() {},
      };
      const clock = createActionClock({
        now: () => now,
        advance: async () => {},
        wait: async (ms) => {
          const end = now + ms;
          if (now < arrival && end >= arrival)
            replay.recordFrame({ direction: "in", elapsedMs: arrival, body: later });
          now = end;
        },
      });
      replay = createNativeReplay({
        wire: {
          open: async ({ opener }) => {
            replay.recordFrame({ direction: "out", elapsedMs: 0, body: opener });
            return stream;
          },
        },
        bindings: { get: (_, id) => id, linkReceive() {} },
        clock,
        cells: [{ id: "S05", group: "G4", variant: "in-stream-deadline-update" }],
      });
      const row = (n, elapsedMs, direction, body) => ({
        n,
        cellId: "S05",
        elapsedMs,
        at: new Date(1000 + elapsedMs).toISOString(),
        direction,
        body,
      });
      try {
        await replay.frame(
          row(1, 0, "out", { subscription: "owned", streamAckDeadlineSeconds: 10 }),
        );
        await replay.frame(row(2, 100, "in", message("same", "first")));
        const update = replay.frame(
          row(3, 200, "out", { modifyDeadlineAckIds: ["first"], modifyDeadlineSeconds: [20] }),
        );
        if (receipt !== 200) {
          await assert.rejects(update, /outbound.*receipt/);
          assert.equal(replay.witnesses.get("S05").completed, false);
        } else {
          await update;
          const result = replay.frame(row(4, 20200, "in", later));
          if (arrival < 20200) await assert.rejects(result, /quiet interval/);
          else {
            await result;
            await replay.action({
              n: 5,
              cellId: "S05",
              elapsedMs: 21200,
              at: new Date(22200).toISOString(),
              event: "stream-case-observation",
              state: { incomplete: false, terminal: null },
            });
            assert.equal(replay.witnesses.get("S05").deadlineUntilMs, 20200);
            assert.equal(replay.witnesses.get("S05").completed, true);
          }
        }
      } finally {
        replay.close();
      }
    }
});

test("natural zero outcome is measured separately while generic native13 remains incomplete", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  const { zeroOutcomeFixture } = await import("./pubsub-production-observation-compare.test.mjs");
  const { makePlan } = await import("./pubsub-observation/plan.mjs");
  for (const received of [0, 1]) {
    let now = 0;
    const observations = [];
    const state = {
      incomplete: true,
      terminal: { code: 13 },
      inboundEnded: true,
      received,
      windowExpired: false,
      windowMs: 90000,
    };
    const replay = createNativeReplay({
      journal: {
        write: (value) => {
          const receipt = { ...value, n: 5001 };
          observations.push(receipt);
          return receipt;
        },
      },
      wire: { open: async () => ({ state: () => state, dispose() {} }) },
      bindings: createBindings(),
      cells: makePlan("s10-diagnostic").cells,
      clock: createActionClock({
        now: () => now++,
        wait: async (ms) => (now += ms),
        advance: async () => {},
      }),
    });
    const input = zeroOutcomeFixture();
    await replay.frame(input.rows[2]);
    await replay.action(input.rows[7]);
    const proof = replay.witnesses.get("S10");
    assert.equal(proof.completed, false);
    assert.deepEqual(proof.zeroOutcome.state, state);
    assert.ok(proof.zeroOutcome.observedElapsedMs >= 0);
    assert.equal(proof.zeroOutcome.observationN, 5001);
    assert.equal(observations[0].elapsedMs, proof.zeroOutcome.observedElapsedMs);
    assert.deepEqual(observations[0].state, proof.zeroOutcome.state);
    replay.close();
  }
});

test("loopback replay retains bounded actual terminal details without inventing absent values", async () => {
  const grpc = (await import("@grpc/grpc-js")).default;
  const { EventEmitter } = await import("node:events");
  const { createReplayClient } = await import("./pubsub-observation/replay-native.mjs");
  const original = grpc.Client.prototype.makeBidiStreamRequest;
  const rpc = new EventEmitter(),
    seen = [];
  grpc.Client.prototype.makeBidiStreamRequest = () => rpc;
  const client = createReplayClient("127.0.0.1:1234", {
    onTerminalDetails: (event, details) => seen.push([event, details]),
  });
  try {
    client.makeBidiStreamRequest(
      "fixture",
      () => {},
      () => {},
      new grpc.Metadata(),
    );
    rpc.emit("error", { code: 13, details: "actual service error" });
    rpc.emit("status", { code: 13, details: "actual service error" });
    rpc.emit("status", { code: 13 });
    assert.deepEqual(seen, [
      ["stream-error", "actual service error"],
      ["stream-status", "actual service error"],
      ["stream-status", undefined],
    ]);
  } finally {
    client.close();
    grpc.Client.prototype.makeBidiStreamRequest = original;
  }
});

const nativeBytes = (body, direction = "in") => {
  const type =
    direction === "in"
      ? protos.google.pubsub.v1.StreamingPullResponse
      : protos.google.pubsub.v1.StreamingPullRequest;
  return Buffer.from(type.encode(type.fromObject(body)).finish());
};

// Synthetic source-bound controls retain S06's three publications and seven native frames.
async function unorderedFlowFixture({
  order = [0, 1, 2],
  ordering = false,
  firstMutation,
  ackMutation,
  batch = false,
  extraAt = null,
  tailExtra = false,
  omitLast = false,
  leaveAck = false,
  duplicateAck = false,
  origin = 0,
  pipeline = false,
  reverseActualDirection = false,
  outboundMutation,
  approvedComparison = false,
  localSeconds = "100",
  localIdentityPrefix = "local",
  publishTime = null,
} = {}) {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  const { makePlan } = await import("./pubsub-observation/plan.mjs");
  const cell = makePlan().cells.find((c) => c.id === "S06");
  const subscription = "projects/fireemu-oracle-idp/subscriptions/fe012345abcdef-s06-sub";
  const topic = "projects/fireemu-oracle-idp/topics/fe012345abcdef-s06-topic";
  const payload = (index) => ({
    data: Buffer.from(`012345abcdef:S06:marker${index}`).toString("base64"),
  });
  const receive = (index, local) => ({
    subscriptionProperties: {},
    receivedMessages: [
      {
        ackId: `${local ? "local" : "source"}-ack-${index}`,
        message: {
          ...payload(index),
          messageId: `${local ? localIdentityPrefix : "source"}-${index}`,
          publishTime: { seconds: local ? localSeconds : "100", nanos: 0 },
        },
      },
    ],
  });
  const nativeRow = (n, elapsedMs, direction, body) => ({
    n,
    cellId: "S06",
    elapsedMs,
    at: new Date(1000 + elapsedMs).toISOString(),
    event: "stream-frame",
    direction,
    body,
    blob: { bytes: nativeBytes(body, direction).length },
    verified: true,
  });
  const frames = [
    nativeRow(179, 0, "out", {
      subscription,
      streamAckDeadlineSeconds: 10,
      maxOutstandingMessages: "1",
      maxOutstandingBytes: "1024",
    }),
    nativeRow(183, 2013, "in", receive(1, false)),
    nativeRow(186, 8035, "out", { ackIds: ["source-ack-1"] }),
    nativeRow(188, 8656, "in", receive(0, false)),
    nativeRow(189, 8664, "out", { ackIds: ["source-ack-0"] }),
    nativeRow(191, 8712, "in", receive(2, false)),
    nativeRow(192, 8718, "out", { ackIds: ["source-ack-2"] }),
  ];
  const sourceCell = {
    ...cell,
    frames,
    exchanges: [
      {
        method: "CreateSubscription",
        request: {
          body: {
            name: subscription,
            topic,
            ...(ordering === true ? { enableMessageOrdering: true } : {}),
          },
        },
        response: {
          ok: true,
          unknown: false,
          body: { name: subscription, enableMessageOrdering: ordering === true },
        },
      },
      {
        method: "GetSubscription",
        request: { body: { name: subscription } },
        response: {
          ok: true,
          unknown: false,
          body: { name: subscription, enableMessageOrdering: ordering === true },
        },
      },
      ...[0, 1, 2].map((index) => ({
        method: "Publish",
        request: { body: { topic, messages: [payload(index)] } },
        response: { ok: true, unknown: false, body: { messageIds: [`source-${index}`] } },
      })),
    ],
  };
  if (ordering === "unknown") sourceCell.exchanges.splice(1, 1);
  const bindings = createBindings();
  for (let index = 0; index < 3; index++)
    bindings.linkPublish(
      { messages: [payload(index)] },
      { messageIds: [`source-${index}`] },
      { messageIds: [`${localIdentityPrefix}-${index}`] },
    );
  let now = origin,
    replay,
    nextIndex = 0,
    received = 0,
    extraSent = false;
  const queue = [],
    acks = [],
    receivedAcks = new Map();
  function record(body, elapsedMs) {
    for (const item of body.receivedMessages ?? [])
      receivedAcks.set(item.message.messageId, item.ackId);
    received++;
    recordFrame({ direction: "in", body, elapsedMs });
    queue.push(body);
  }
  function advance(ms) {
    const end = now + ms;
    if (extraAt !== null && !extraSent && end - origin >= extraAt) {
      extraSent = true;
      record(receive(order[1], true), extraAt);
    }
    now = end;
  }
  const stream = {
    async next(timeout) {
      if (queue.length) return queue.shift();
      advance(timeout);
      return queue.shift() ?? null;
    },
    write(body) {
      outboundMutation?.(body);
      acks.push(...body.ackIds);
      recordFrame({ direction: "out", body, elapsedMs: now - origin });
      if (nextIndex < 3) record(receive(order[nextIndex++], true), now - origin + 1);
      else if (tailExtra) record(receive(order[0], true), now - origin + 1);
    },
    state: () => ({ incomplete: false, terminal: null, received }),
    dispose() {},
  };
  let recordFrame = (frame) => replay.recordFrame(frame);
  const open = async ({ opener }) => {
    recordFrame({ direction: "out", body: opener, elapsedMs: now - origin });
    const body = receive(order[nextIndex++], true);
    if (batch)
      body.receivedMessages = order.map((index) => receive(index, true).receivedMessages[0]);
    firstMutation?.(body);
    record(body, 2);
    return stream;
  };
  if (pipeline) {
    const { replayA } = await import("./pubsub-observation/replay.mjs");
    const input = fixture();
    input.rows = [input.rows[0]];
    for (const exchange of sourceCell.exchanges) {
      const requestId = input.rows.length;
      input.rows.push({
        event: "request-dispatch",
        cellId: "S06",
        requestId,
        method: exchange.method,
        transport: "grpc",
        category: "target",
        request: exchange.request.body,
      });
      input.rows.push({
        event: "response",
        durationMs: 0,
        cellId: "S06",
        requestId,
        method: exchange.method,
        transport: "grpc",
        reply: { code: "OK", ...exchange.response },
      });
    }
    for (const frame of frames)
      input.rows.push({ ...frame, at: new Date(20000 + frame.elapsedMs).toISOString() });
    input.rows.push({
      event: "stream-case-observation",
      cellId: "S06",
      elapsedMs: 8740,
      at: new Date(28740).toISOString(),
      state: { incomplete: false, terminal: null },
      invalidAckObservedMs: null,
    });
    input.rows.push({
      event: "case-result",
      cellId: "S06",
      at: new Date(28741).toISOString(),
      complete: true,
      cleanupClosed: true,
      budgetOverrun: false,
    });
    input.rows = input.rows.map((row, index) => ({
      ...row,
      n: index + 1,
      at: row.at ?? new Date(1000 + index * 1000).toISOString(),
    }));
    input.verifiedFrames = new Set(
      input.rows.filter((row) => row.event === "stream-frame").map((row) => row.n),
    );
    for (const row of input.rows.filter((r) => r.event === "stream-frame"))
      row.blob.sha256 = createHash("sha256")
        .update(nativeBytes(row.body, row.direction))
        .digest("hex");
    input.summary.results = [
      { cellId: "S06", complete: true, cleanupClosed: true, budgetOverrun: false },
    ];
    let publication = 0;
    const report = await replayA(
      input,
      {
        PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
        FIREEMU_CONTROL_URL: "http://127.0.0.1:4321/v1/",
        FIREEMU_CONTROL_TOKEN: "synthetic-control",
      },
      {
        profile: "release",
        rustcWrapper: "",
        path: "/fixture/release/fireemu",
        head: "a".repeat(40),
        sha256: "b".repeat(64),
        command: ["cargo", "build", "--release"],
      },
      {
        now: () => now,
        wait: async (ms) => advance(ms),
        advance: async () => {},
        wireFactory: ({ journal }) => {
          recordFrame = (frame) =>
            journal.frame(nativeBytes(frame.body, frame.direction), {
              event: "stream-frame",
              cellId: "S06",
              ...frame,
              direction:
                reverseActualDirection && frame.direction === "in" ? "out" : frame.direction,
            });
          return {
            open,
            close() {},
            call: async ({ method, request }) => {
              const exchange = sourceCell.exchanges.find((e) => e.method === method);
              journal.write({ event: "request-dispatch", cellId: "S06", method, request });
              const reply = {
                ...exchange.response,
                code: "OK",
                body:
                  method === "Publish"
                    ? { messageIds: [`${localIdentityPrefix}-${publication++}`] }
                    : exchange.response.body,
              };
              journal.write({ event: "response", cellId: "S06", method, reply });
              return reply;
            },
          };
        },
      },
    );
    assert.equal(report.nativeWitnesses.S06.completed, true);
    assert.equal(report.parentClosureReady, false);
    assert.deepEqual(
      acks,
      order.map((index) => receivedAcks.get(`${localIdentityPrefix}-${index}`)),
    );
    if (approvedComparison) {
      const source = validateReplaySource(input);
      const local = {
        ...source,
        cells: source.cells.map((cell) => ({
          ...cell,
          frames: report.localRows
            .filter((r) => r.cellId === cell.id && r.event === "stream-frame")
            .map((r) => ({ ...r, verified: true })),
          events: report.localRows.filter(
            (r) => r.cellId === cell.id && r.event.startsWith("stream-"),
          ),
        })),
      };
      const authorityBytes = Buffer.from(
        JSON.stringify({
          proposalSha256: "d".repeat(64),
          line: "Explicit offline ACK disposition",
        }),
      );
      const disposition = {
        authority: {
          bytes: authorityBytes,
          sha256: createHash("sha256").update(authorityBytes).digest("hex"),
        },
        source: {
          runId: source.runId,
          packetSha256: source.packetSha256,
          descriptorSha256: source.descriptorSha256,
        },
        rawFrames: source.cells.flatMap((cell) =>
          cell.frames.map((frame, i) => {
            const peer = local.cells.find((c) => c.id === cell.id).frames[i];
            return {
              sourceN: frame.n,
              localN: peer.n,
              sourceBytes: nativeBytes(frame.body, frame.direction),
              localBytes: nativeBytes(peer.body, peer.direction),
            };
          }),
        ),
        remainingDebts: {},
      };
      return compareExecutedObservation(source, local, report.nativeWitnesses, disposition);
    }
    return report;
  }
  replay = createNativeReplay({
    cells: [cell],
    sourceCells: [sourceCell],
    bindings,
    publishTime,
    clock: createActionClock({
      now: () => now,
      wait: async (ms) => advance(ms),
      advance: async () => {},
    }),
    wire: { open },
  });
  try {
    await replay.frame(frames[0]);
    for (const sourceRow of frames.slice(1)) {
      if ((omitLast && sourceRow.n >= 191) || (leaveAck && sourceRow.n === 192)) continue;
      const next = structuredClone(sourceRow);
      if (next.n === 186) ackMutation?.(next.body);
      await replay.frame(next);
      if (duplicateAck && next.n === 186)
        await replay.frame({ ...next, n: 187, elapsedMs: 8036, at: new Date(9036).toISOString() });
    }
    await replay.action({
      n: 194,
      cellId: "S06",
      event: "stream-case-observation",
      elapsedMs: 8740,
      at: new Date(9740).toISOString(),
      state: { incomplete: false, terminal: null },
      invalidAckObservedMs: null,
    });
    assert.equal(replay.witnesses.get("S06").completed, true);
    assert.deepEqual(
      acks,
      order.map((index) => `local-ack-${index}`),
    );
    for (let index = 0; index < 3; index++) {
      assert.equal(bindings.get("message", `source-${index}`), `${localIdentityPrefix}-${index}`);
      assert.equal(bindings.get("ack", `source-ack-${index}`), `local-ack-${index}`);
    }
    return acks;
  } finally {
    replay.close();
  }
}

test("unordered S06 follows each actual owned token for all six legal single-message permutations", async () => {
  for (const order of [
    [1, 0, 2],
    [0, 1, 2],
    [0, 2, 1],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ])
    await assert.doesNotReject(unorderedFlowFixture({ order }));
});

test("unordered native receive refuses a proof from another cell", async () => {
  await assert.rejects(
    unorderedFlowFixture({ publishTime: () => ({ cellId: "S01" }) }),
    /publication proof cell mismatch/,
  );
});

test("S06 unordered selection requires a recorded disabled ordering configuration", async () => {
  await assert.doesNotReject(unorderedFlowFixture({ order: [1, 0, 2], ordering: true }));
  await assert.rejects(unorderedFlowFixture({ ordering: true }), /binding|semantic/);
  await assert.rejects(unorderedFlowFixture({ ordering: "unknown" }), /ordering/);
});

test("S06 unordered identity, payload, attribute and live ACK controls fail closed", async () => {
  for (const firstMutation of [
    (body) => (body.receivedMessages[0].message.messageId = "foreign"),
    (body) => (body.receivedMessages[0].message.data = "Zm9yZWlnbg=="),
    (body) => (body.receivedMessages[0].message.attributes = { foreign: "true" }),
    (body) => (body.receivedMessages[0].message.orderingKey = "unexpected-key"),
    (body) => (body.receivedMessages[0].deliveryAttempt = 2),
    (body) => delete body.receivedMessages[0].message.data,
  ])
    await assert.rejects(unorderedFlowFixture({ firstMutation }), /binding|semantic|owned/);
  await assert.rejects(
    unorderedFlowFixture({ ackMutation: (body) => (body.ackIds = ["source-ack-0"]) }),
    /ACK slot/,
  );
  await assert.rejects(unorderedFlowFixture({ duplicateAck: true }), /ACK slot/);
  await assert.rejects(unorderedFlowFixture({ order: [0, 0, 2] }), /binding|owned|duplicate/);
  await assert.rejects(unorderedFlowFixture({ omitLast: true }), /multiset|owned/);
  await assert.rejects(unorderedFlowFixture({ leaveAck: true }), /multiset|ACK/);
  await assert.rejects(unorderedFlowFixture({ tailExtra: true }), /multiset|owned/);
});

test("S06 unordered matching still rejects the actual three-before-ACK shape and queued early frames", async () => {
  await assert.rejects(unorderedFlowFixture({ batch: true }), /cardinality/);
  await assert.rejects(unorderedFlowFixture({ extraAt: 8020 }), /quiet interval/);
  await assert.doesNotReject(unorderedFlowFixture({ origin: 2700000 }));
});

test("executed replay passes the admitted S06 source cell to unordered token matching", async () => {
  await assert.doesNotReject(unorderedFlowFixture({ pipeline: true }));
});

test("executed native semantics keep dynamic widths separate from literal physical gaps", async () => {
  const report = await unorderedFlowFixture({ pipeline: true });
  const cell = report.cells.find((c) => c.id === "S06");
  assert.equal(cell.nativeSemantics.verdict, "MATCH");
  assert.equal(cell.nativeLayout.verdict, "DIVERGES");
  assert.equal(cell.verdict, "DIVERGES");
  assert.equal(report.parentClosureReady, false);
  assert.equal(cell.nativeLayout.frames.length, 7);
});

test("approved comparison consumes executed receive and ACK guards without erasing non-ACK widths", async () => {
  const matched = await unorderedFlowFixture({
    pipeline: true,
    approvedComparison: true,
    order: [1, 0, 2],
    localSeconds: "100",
    localIdentityPrefix: "actual",
  });
  const cell = matched.cells.find((c) => c.id === "S06");
  assert.equal(cell.nativeSemantics.verdict, "MATCH");
  assert.equal(cell.nativeLayout.verdict, "DIVERGES");
  assert.equal(cell.approvedComparison.verdict, "MATCH");
  assert.equal(matched.parentClosureReady, false);
  const residual = await unorderedFlowFixture({
    pipeline: true,
    approvedComparison: true,
    order: [1, 0, 2],
  });
  assert.equal(residual.cells.find((c) => c.id === "S06").approvedComparison.verdict, "DIVERGES");
  for (const options of [
    { batch: true },
    { extraAt: 8020 },
    { outboundMutation: (body) => (body.ackIds[0] = "foreign-actual-ack") },
    { outboundMutation: (body) => body.ackIds.push(body.ackIds[0]) },
    { firstMutation: (body) => delete body.receivedMessages[0].message.publishTime },
    { firstMutation: (body) => (body.receivedMessages[0].message.data = "Zm9yZWlnbg==") },
  ])
    await assert.rejects(
      unorderedFlowFixture({ pipeline: true, approvedComparison: true, ...options }),
      /outbound semantic|timestamp|binding|semantic|quiet|cardinality/,
    );
});

test("executed replay rejects equal-byte payload changes and compensated timestamp absence", async () => {
  for (const firstMutation of [
    (body) => {
      const before = nativeBytes(body).length;
      const data = Buffer.from(body.receivedMessages[0].message.data, "base64");
      data[0] ^= 1;
      body.receivedMessages[0].message.data = data.toString("base64");
      assert.equal(nativeBytes(body).length, before);
    },
    (body) => {
      const before = nativeBytes(body).length;
      delete body.receivedMessages[0].message.publishTime;
      const padding = before - nativeBytes(body).length;
      body.receivedMessages[0].ackId += "p".repeat(padding);
      assert.equal(nativeBytes(body).length, before);
    },
  ])
    await assert.rejects(
      unorderedFlowFixture({ pipeline: true, firstMutation }),
      /binding|semantic|timestamp/,
    );
});

test("executed receive requires corresponding presence and a legal decoded Timestamp", async () => {
  for (const publishTime of [
    null,
    undefined,
    [],
    { seconds: "NaN" },
    { seconds: "1.5" },
    { seconds: "253402300800" },
    { seconds: "-62135596801" },
    { nanos: -1 },
    { nanos: 1000000000 },
    { nanos: 0.5 },
    { seconds: true },
    { unknown: 1 },
  ])
    await assert.rejects(
      unorderedFlowFixture({
        pipeline: true,
        firstMutation: (body) => {
          body.receivedMessages[0].message.publishTime = publishTime;
        },
      }),
      /timestamp/,
    );
  for (const publishTime of [
    {},
    { seconds: "-62135596800", nanos: 0 },
    { seconds: "253402300799", nanos: 999999999 },
    { seconds: 1, nanos: 1 },
  ]) {
    const bindings = createBindings();
    bindings.linkPublish(
      { messages: [{ data: "bWFya2Vy" }] },
      { messageIds: ["source"] },
      { messageIds: ["local"] },
    );
    const source = message("source", "source-ack");
    const local = message("local", "local-ack");
    source.receivedMessages[0].message.publishTime = structuredClone(publishTime);
    local.receivedMessages[0].message.publishTime = structuredClone(publishTime);
    assert.doesNotThrow(() => matchNativeReceive(source, local, bindings));
  }
  for (const localSeconds of ["101", "200"])
    await assert.rejects(
      unorderedFlowFixture({ pipeline: true, localSeconds }),
      /native receive semantic mismatch/,
    );
});

test("executed semantic witness keeps direction, subscription presence and credit controls", async () => {
  await assert.rejects(
    unorderedFlowFixture({ pipeline: true, reverseActualDirection: true }),
    /timestamp|quiet/,
  );
  await assert.rejects(
    unorderedFlowFixture({
      pipeline: true,
      firstMutation: (body) => {
        delete body.subscriptionProperties;
      },
    }),
    /semantic/,
  );
  await assert.rejects(unorderedFlowFixture({ pipeline: true, batch: true }), /cardinality/);
  await assert.rejects(unorderedFlowFixture({ pipeline: true, extraAt: 8020 }), /quiet interval/);
});

test("executed replay refuses foreign and duplicate actual outbound ACK receipts", async () => {
  for (const outboundMutation of [
    (body) => (body.ackIds[0] = "foreign-actual-ack"),
    (body) => body.ackIds.push(body.ackIds[0]),
  ])
    await assert.rejects(
      unorderedFlowFixture({ pipeline: true, outboundMutation }),
      /outbound semantic/,
    );
});

test("S03 recorded dispose awaits bounded actual diagnostic callbacks after a null observation", async () => {
  const { createNativeReplay } = await import("./pubsub-observation/replay-native.mjs");
  const { openStream } = await import("./pubsub-observation/stream.mjs");
  const { EventEmitter } = await import("node:events");
  for (const failure of [false, true, "missing-status"]) {
    let now = 0,
      cancelled = 0,
      replay;
    const rows = [];
    const rpc = new EventEmitter();
    rpc.write = () => true;
    rpc.cancel = () => {
      cancelled++;
      queueMicrotask(() => {
        rpc.emit("error", { code: 1, details: "Cancelled on client" });
        if (failure !== "missing-status")
          rpc.emit("status", { code: 1, details: "Cancelled on client" });
      });
    };
    const journal = {
      write: (row) => {
        if (failure === true && row.event === "stream-status")
          throw new Error("diagnostic persistence failed");
        const entry = { ...structuredClone(row), n: rows.length + 1 };
        rows.push(entry);
        return entry;
      },
      frame: (_bytes, row) => replay.recordFrame(row),
    };
    replay = createNativeReplay({
      journal,
      bindings: createBindings(),
      cells: [{ id: "S03", group: "G4", variant: "ack-received-token" }],
      clock: createActionClock({
        now: () => now,
        wait: async (ms) => (now += ms),
        advance: async () => {},
      }),
      wire: {
        open: (options) =>
          openStream({
            ...options,
            journal,
            credential: async () => "synthetic",
            meter: { start() {}, frame() {}, remaining: () => 90001, clock: () => now },
            client: { makeBidiStreamRequest: () => rpc },
          }),
      },
    });
    try {
      await replay.frame({
        n: 16,
        cellId: "S03",
        direction: "out",
        elapsedMs: 0,
        at: new Date(1000).toISOString(),
        body: { subscription: "owned", streamAckDeadlineSeconds: 10 },
      });
      await replay.action({
        n: 22,
        cellId: "S03",
        event: "stream-case-observation",
        elapsedMs: 1000,
        at: new Date(2000).toISOString(),
        state: { incomplete: false, terminal: null },
        invalidAckObservedMs: null,
      });
      const observation = rows.find((r) => r.event === "stream-case-observation");
      assert.equal(observation?.state.terminal, null);
      const disposal = replay.action({
        n: 23,
        cellId: "S03",
        event: "stream-cancel",
        reason: "dispose",
        elapsedMs: 1001,
        at: new Date(2001).toISOString(),
      });
      if (failure === true) {
        await assert.rejects(disposal, /diagnostic persistence failed/);
        assert.equal(replay.witnesses.get("S03").completed, false);
        assert.equal(replay.witnesses.get("S03").semanticsVerified, false);
      } else {
        await disposal;
        assert.equal(cancelled, 1);
        const expected = [["stream-error", 1, "Cancelled on client", "disposal", "dispose"]];
        if (failure !== "missing-status")
          expected.push(["stream-status", 1, "Cancelled on client", "disposal", "dispose"]);
        assert.deepEqual(
          rows
            .filter((r) => ["stream-error", "stream-status"].includes(r.event))
            .map((r) => [r.event, r.code, r.details, r.phase, r.cancelReason]),
          expected,
        );
        assert.equal(observation.state.terminal, null);
      }
    } finally {
      replay.close();
    }
  }
});

test("explicit generated publishTime requires successful readback and publication identity", async () => {
  const proof = generatedTimeProof();
  const source = message("source", "source-ack"),
    local = message("local", "local-ack");
  source.receivedMessages[0].message.publishTime = { seconds: "1791508662", nanos: 21000000 };
  local.receivedMessages[0].message.publishTime = { seconds: "1791508661", nanos: 899000000 };
  const bindings = () => {
    const b = createBindings();
    b.linkPublish(
      proof.publications[0].sourceRequest,
      { messageIds: ["source"] },
      { messageIds: ["local"] },
    );
    return b;
  };
  assert.equal(matchNativeReceive(source, local, bindings(), proof), "MATCH");
  assert.throws(() => matchNativeReceive(source, local, bindings()), /semantic mismatch/);
  for (const alter of [
    (p) => p.publications.splice(0),
    (p) => {
      p.publications[0].sourceRequest.messages[0].data = "d3Jvbmc=";
      p.publications[0].localRequest.messages[0].data = "d3Jvbmc=";
    },
    (p) => {
      const bytes = Buffer.from(
        JSON.stringify({
          ownerRow: 1100,
          proposalSha256: "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53",
        }),
      );
      p.authority = { bytes, sha256: createHash("sha256").update(bytes).digest("hex") };
    },
    (p) => delete p.publications[0].clock.body,
    (p) => (p.publications[0].clock.status = 503),
    (p) => (p.publications[0].sourceReply.ok = false),
    (p) => (p.publications[0].sourceRequest.topic = "foreign"),
    (p) => (p.compiledInputs.inputsSha256 = "c".repeat(64)),
    (p) => (p.subscription.localReply.body.topic = "foreign"),
    (p) => (p.publications[0].clock.responseSha256 = "c".repeat(64)),
    (p) => (p.authority.bytes = Buffer.from("{}")),
  ]) {
    const missing = generatedTimeProof();
    alter(missing);
    assert.equal(matchNativeReceive(source, local, bindings(), missing), "NOT_COMPARABLE");
  }
  for (const alter of [
    (p) => (p.publications[0].clock.body.clock = "2026-10-09T01:17:41.898Z"),
    (p) =>
      p.deliveries.push({
        messageId: "local",
        publishTime: { seconds: "1791508661", nanos: 898000000 },
      }),
  ]) {
    const wrong = generatedTimeProof();
    alter(wrong);
    const clock = wrong.publications[0].clock,
      bytes = Buffer.from(JSON.stringify(clock.body));
    clock.responseBytes = bytes.toString("base64");
    clock.responseSha256 = createHash("sha256").update(bytes).digest("hex");
    assert.throws(
      () => matchNativeReceive(source, local, bindings(), wrong),
      /publication timestamp mismatch/,
    );
  }
  for (const alter of [
    (b) => b.receivedMessages[0].message.publishTime.nanos++,
    (b) => delete b.receivedMessages[0].message.publishTime.seconds,
    (b) => (b.receivedMessages[0].message.publishTime.nanos = 1000000000),
    (b) => (b.receivedMessages[0].message.orderingKey = "other"),
    (b) => (b.subscriptionProperties = { retainAckedMessages: true }),
  ]) {
    const wrong = structuredClone(local);
    alter(wrong);
    assert.throws(() => matchNativeReceive(source, wrong, bindings(), generatedTimeProof()));
  }
});

for (const cellId of ["S03", "S01"])
  test(`${cellId} replay persists actual clock readback before Publish and carries generated-time proof`, async () => {
    const { replayA } = await import("./pubsub-observation/replay.mjs");
    const base = Date.parse("2026-10-09T01:17:41.899Z"),
      topic = "projects/fireemu-oracle-idp/topics/fe012345abcdef-s03-topic",
      subscription = "projects/fireemu-oracle-idp/subscriptions/fe012345abcdef-s03-sub";
    const encode = (body, direction) =>
      Buffer.from(
        protos.google.pubsub.v1[
          direction === "out" ? "StreamingPullRequest" : "StreamingPullResponse"
        ]
          .encode(
            protos.google.pubsub.v1[
              direction === "out" ? "StreamingPullRequest" : "StreamingPullResponse"
            ].fromObject(body),
          )
          .finish(),
      );
    for (const variant of [
      "valid",
      "foreign-publication",
      "invalid-identifiers",
      "missing-readback",
      "wrong-readback",
      "wrong-received",
    ]) {
      const sourceId = variant === "invalid-identifiers" ? "source" : "1234567890123456";
      const localId = variant === "invalid-identifiers" ? "local" : "9876543210987654";
      const actualBlobs = new Map();
      const input = fixture(),
        proof = generatedTimeProof(),
        saved = [],
        frameBytes = new Map();
      const success = (body) => ({
        ok: true,
        status: 200,
        code: "OK",
        unknown: false,
        body,
        bodyBytes: 2,
      });
      const exchanges = [
        ["CreateTopic", { name: topic }, { name: topic }],
        ["CreateSubscription", { name: subscription, topic }, { name: subscription, topic }],
        ["Publish", { topic, messages: [{ data: "bWFya2Vy" }] }, { messageIds: [sourceId] }],
      ];
      input.rows = [input.rows[0]];
      if (variant === "foreign-publication") {
        const requestId = input.rows.length;
        input.rows.push(
          {
            event: "request-dispatch",
            cellId: "S02",
            requestId,
            method: "Publish",
            transport: "grpc",
            category: "target",
            request: { topic, messages: [{ data: "Zm9yZWlnbg==" }] },
          },
          {
            event: "response",
            cellId: "S02",
            requestId,
            method: "Publish",
            transport: "grpc",
            durationMs: 0,
            reply: success({ messageIds: ["2222222222222222"] }),
          },
        );
      }
      for (const [method, request, body] of exchanges) {
        const requestId = input.rows.length;
        input.rows.push({
          event: "request-dispatch",
          cellId,
          requestId,
          method,
          transport: "grpc",
          category: "target",
          request,
        });
        input.rows.push({
          event: "response",
          cellId,
          requestId,
          method,
          transport: "grpc",
          durationMs: 0,
          reply: success(body),
        });
      }
      const opener = { subscription, streamAckDeadlineSeconds: 10 };
      const sourceReceive = message(sourceId, "source-ack"),
        localReceive = message(localId, "longer-local-ack");
      sourceReceive.receivedMessages[0].message.publishTime = {
        seconds: "1791508662",
        nanos: cellId === "S01" ? 26000000 : 21000000,
      };
      localReceive.receivedMessages[0].message.publishTime = {
        seconds: "1791508661",
        nanos: variant === "wrong-received" ? 898000000 : 899000000,
      };
      for (const [direction, body, elapsedMs] of [
        ["out", opener, 0],
        ["in", sourceReceive, 1],
      ]) {
        const raw = encode(body, direction);
        input.rows.push({
          event: "stream-frame",
          cellId,
          direction,
          body,
          elapsedMs,
          blob: { bytes: raw.length, sha256: createHash("sha256").update(raw).digest("hex") },
        });
      }
      input.rows.push({
        event: "stream-case-observation",
        cellId,
        elapsedMs: 2,
        state: { incomplete: false, terminal: null },
        invalidAckObservedMs: null,
      });
      input.rows.push({
        event: "case-result",
        cellId,
        complete: true,
        cleanupClosed: true,
        budgetOverrun: false,
      });
      const offset = variant === "foreign-publication" ? 2 : 0;
      input.rows = input.rows.map((row, i) => ({
        ...row,
        n: i + 1,
        at: new Date(
          i <= 5 + offset ? base - 10 + i : base + Math.max(0, i - 6 - offset),
        ).toISOString(),
      }));
      // The owned Publish uses the fixed publication instant.
      input.rows[5 + offset].at = new Date(base).toISOString();
      input.rows[6 + offset].at = new Date(base).toISOString();
      input.verifiedFrames = new Set(
        input.rows.filter((r) => r.event === "stream-frame").map((r) => r.n),
      );
      input.summary.results = [
        { cellId, complete: true, cleanupClosed: true, budgetOverrun: false },
      ];
      const source = validateReplaySource(input);
      proof.source = {
        runId: source.runId,
        packetSha256: source.packetSha256,
        descriptorSha256: source.descriptorSha256,
      };
      for (const row of input.rows.filter((r) => r.event === "stream-frame"))
        frameBytes.set(row.n, encode(row.body, row.direction));
      let now = 0,
        journal,
        actualClock;
      const run = replayA(
        input,
        {
          PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
          FIREEMU_CONTROL_URL: "http://127.0.0.1:4321/v1/",
          FIREEMU_CONTROL_TOKEN: "synthetic",
        },
        {
          profile: "release",
          rustcWrapper: "",
          path: "/fixture/release/fireemu",
          head: "a".repeat(40),
          sha256: "b".repeat(64),
          command: ["cargo", "build", "--release"],
        },
        {
          publishTimeDisposition: {
            authority: proof.authority,
            source: proof.source,
            publishTime: proof,
            sourceFrameBytes: frameBytes,
          },
          now: () => now,
          wait: async (ms) => {
            now += ms;
          },
          persist: (row, bytes) => {
            if (bytes) actualBlobs.set(row.blob.sha256, Buffer.from(bytes));
            else saved.push(row);
          },
          advance: async (receipt) => {
            actualClock = receipt.instant;
            const body = {
              clock:
                variant === "wrong-readback"
                  ? new Date(Date.parse(receipt.instant) - 1).toISOString()
                  : receipt.instant,
              backwardsSets: 0,
            };
            return variant === "missing-readback"
              ? undefined
              : { status: 200, body, bytes: Buffer.from(JSON.stringify(body)) };
          },
          wireFactory: (options) => {
            journal = options.journal;
            return {
              close() {},
              call: async ({ method, request, cellId: requestCell }) => {
                assert.ok(
                  saved.some((r) => r.event === "clock-control" && r.instant === actualClock),
                );
                journal.write({ event: "request-dispatch", cellId: requestCell, method, request });
                const reply = success(
                  method === "Publish"
                    ? {
                        messageIds: [
                          request.messages[0].data === "Zm9yZWlnbg=="
                            ? "1111111111111111"
                            : localId,
                        ],
                      }
                    : exchanges.find((e) => e[0] === method)[2],
                );
                journal.write({ event: "response", cellId: requestCell, method, reply });
                return reply;
              },
              open: async ({ opener: actualOpener }) => {
                const writes = [];
                const stream = {
                  write(body) {
                    const bytes = encode(body, "out");
                    writes.push(bytes);
                    journal.frame(bytes, {
                      event: "stream-frame",
                      cellId,
                      direction: "out",
                      elapsedMs: now,
                      body,
                    });
                  },
                  next: async () => {
                    journal.frame(encode(localReceive, "in"), {
                      event: "stream-frame",
                      cellId,
                      direction: "in",
                      elapsedMs: now,
                      body: localReceive,
                    });
                    return localReceive;
                  },
                  state: () => ({ incomplete: false, terminal: null }),
                  dispose() {},
                };
                stream.write(actualOpener);
                assert.equal(writes.length, 1);
                return stream;
              },
            };
          },
        },
      );
      if (["wrong-readback", "wrong-received"].includes(variant)) {
        await assert.rejects(run, /publication timestamp mismatch/);
        continue;
      }
      const report = await run,
        witness = report.nativeWitnesses[cellId];
      assert.equal(
        witness.semanticsVerified,
        ["valid", "foreign-publication", "invalid-identifiers"].includes(variant),
      );
      assert.equal(witness.publishTime.cellId, cellId);
      assert.equal(witness.publishTime.publications.length, 1);
      assert.equal(witness.publishTime.publications[0].clock.sourceDispatchN, 6 + offset);
      assert.equal(witness.publishTime.publications[0].clock.instant, new Date(base).toISOString());
      assert.equal(
        report.cells.find((c) => c.id === cellId).approvedComparison.verdict,
        ["valid", "foreign-publication"].includes(variant)
          ? "MATCH"
          : variant === "invalid-identifiers"
            ? "DIVERGES"
            : "NOT_COMPARABLE",
        JSON.stringify(report.cells.find((c) => c.id === cellId)),
      );
      const frames = report.localRows.filter(
        (r) => r.event === "stream-frame" && r.cellId === cellId,
      );
      assert.deepEqual(
        frames.map((f) => f.direction),
        ["out", "in"],
      );
      for (const frame of frames) {
        const bytes = actualBlobs.get(frame.blob.sha256);
        assert.equal(bytes.length, frame.blob.bytes);
        assert.equal(createHash("sha256").update(bytes).digest("hex"), frame.blob.sha256);
      }
      if (variant === "invalid-identifiers")
        assert.equal(
          report.cells.find((c) => c.id === cellId).rows.find((r) => r.method === "Publish")
            .verdict,
          "DIVERGES",
        );
      if (["valid", "foreign-publication"].includes(variant))
        assert.equal(report.cells.find((c) => c.id === cellId).nativeLayout.verdict, "DIVERGES");
      assert.equal(report.parentClosureReady, false);
    }
  });
