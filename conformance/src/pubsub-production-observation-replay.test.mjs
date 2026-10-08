import test from "node:test";
import assert from "node:assert/strict";
import { createBindings } from "./pubsub-production/stream-dlq-compare-core.mjs";
import {
  rewriteNativeFrame,
  matchNativeReceive,
  createActionClock,
} from "./pubsub-observation/replay-native.mjs";
import { validateReplaySource } from "./pubsub-observation/replay.mjs";
import { fixture } from "./pubsub-production-observation-compare.test.mjs";

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
