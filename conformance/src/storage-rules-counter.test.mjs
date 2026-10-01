import assert from "node:assert/strict";
import test from "node:test";
import {
  createStage3RequestCounter,
  DRAFT_REQUEST_LIMITS,
} from "./storage-rules/request-counter.mjs";

function counter(preflightIds = ["preflight/a"]) {
  const events = [];
  const value = createStage3RequestCounter({
    preflightIds,
    onStarted: async (row) => events.push(["started", row]),
    onReserve: async (row) => events.push(["reserve", row]),
    onTerminal: async (row) => events.push(["terminal", row]),
  });
  return { value, events };
}

test("stage 3 counts preflight after the started row and writes a terminal on refusal", async () => {
  const { value, events } = counter(["preflight/release"]);
  await assert.rejects(
    value.send("preflight/release", async () => 404),
    /started/,
  );
  await value.start({ runId: "run-a" });
  await assert.rejects(
    value.sendPreflight(
      "preflight/release",
      async () => {
        assert.deepEqual(
          events.map(([type]) => type),
          ["started", "reserve"],
        );
        return 500;
      },
      (status) => status === 404,
    ),
    /preflight/,
  );
  assert.deepEqual(
    events.map(([type]) => type),
    ["started", "reserve", "terminal"],
  );
  assert.equal(events[1][1].attempt, 1);
  assert.equal(events[2][1].requests, 1);
  assert.equal(events[2][1].outcome, "preflight-failed");
  await assert.rejects(
    value.send("subject/after-close", async () => 200),
    /closed/,
  );
});

test("normal requests cannot borrow the protected recovery reserve", async () => {
  assert.deepEqual(DRAFT_REQUEST_LIMITS, { maxRequests: 6648, recoveryReserve: 2000 });
  const { value, events } = counter();
  await value.start({ runId: "run-a" });
  await value.sendPreflight(
    "preflight/a",
    async () => 200,
    (status) => status === 200,
  );
  value.admit();
  for (let index = 0; index < 4647; index++) {
    await value.send(`subject/${index}`, async () => 200);
  }
  await assert.rejects(
    value.send("subject/over-cap", async () => 200),
    /normal cap/,
  );
  value.enterRecovery();
  for (let index = 0; index < 2000; index++) {
    await value.send(`recovery/${index}`, async () => 200);
  }
  await assert.rejects(
    value.send("recovery/over-cap", async () => 200),
    /recovery cap/,
  );
  await value.finish("needs-recovery");
  assert.equal(events.at(-1)[1].requests, 6648);
  assert.equal(
    events.filter(([type, row]) => type === "reserve" && row.phase === "preflight").length,
    1,
  );
  assert.equal(
    events.filter(([type, row]) => type === "reserve" && row.phase === "normal").length,
    4647,
  );
  assert.equal(
    events.filter(([type, row]) => type === "reserve" && row.phase === "recovery").length,
    2000,
  );
});

test("an uncertain send enters recovery and cannot be repeated", async () => {
  const { value } = counter();
  await value.start({ runId: "run-a" });
  await value.sendPreflight(
    "preflight/a",
    async () => 200,
    (status) => status === 200,
  );
  value.admit();
  await assert.rejects(
    value.send("subject/uncertain", async () => {
      throw new Error("connection reset");
    }),
    /connection reset/,
  );
  assert.equal(value.snapshot().mode, "recovery");
  await assert.rejects(
    value.send("subject/uncertain", async () => 200),
    /duplicate/,
  );
  await value.send("recovery/readback", async () => 200);
  assert.equal(value.snapshot().requests, 3);
});

test("a failed durable reservation or concurrent dispatch blocks new traffic", async () => {
  const blocked = createStage3RequestCounter({
    preflightIds: ["preflight/a"],
    onStarted: async () => {},
    onReserve: async () => {
      throw new Error("fsync failed");
    },
    onTerminal: async () => {},
  });
  await blocked.start({ runId: "run-a" });
  let dispatched = false;
  await assert.rejects(
    blocked.sendPreflight(
      "preflight/a",
      async () => {
        dispatched = true;
      },
      () => true,
    ),
    /fsync failed/,
  );
  assert.equal(dispatched, false);
  assert.equal(blocked.snapshot().mode, "journal-uncertain");
  await assert.rejects(
    blocked.send("preflight/b", async () => 200),
    /journal/,
  );

  const { value } = counter();
  await value.start({ runId: "run-b" });
  await value.sendPreflight(
    "preflight/a",
    async () => 200,
    (status) => status === 200,
  );
  value.admit();
  let release;
  const pending = value.send(
    "subject/a",
    () =>
      new Promise((resolve) => {
        release = resolve;
      }),
  );
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(
    value.send("subject/b", async () => 200),
    /concurrent/,
  );
  release(200);
  assert.equal(await pending, 200);
});

test("uncertain started or terminal writes fail closed and limits cannot grow", async () => {
  assert.throws(
    () =>
      createStage3RequestCounter({
        maxRequests: 6649,
        preflightIds: ["preflight/a"],
        onStarted: async () => {},
        onReserve: async () => {},
        onTerminal: async () => {},
      }),
    /envelope/,
  );
  const badStart = createStage3RequestCounter({
    preflightIds: ["preflight/a"],
    onStarted: async () => {
      throw new Error("started fsync failed");
    },
    onReserve: async () => {},
    onTerminal: async () => {},
  });
  await assert.rejects(badStart.start({ runId: "run-a" }), /started fsync failed/);
  assert.equal(badStart.snapshot().mode, "journal-uncertain");
  await assert.rejects(
    badStart.send("preflight/a", async () => 200),
    /journal/,
  );

  const badTerminal = createStage3RequestCounter({
    preflightIds: ["preflight/a"],
    onStarted: async () => {},
    onReserve: async () => {},
    onTerminal: async () => {
      throw new Error("terminal fsync failed");
    },
  });
  await badTerminal.start({ runId: "run-b" });
  await assert.rejects(
    badTerminal.sendPreflight(
      "preflight/a",
      async () => 500,
      (status) => status === 200,
    ),
    /terminal fsync failed/,
  );
  assert.equal(badTerminal.snapshot().mode, "journal-uncertain");
  await assert.rejects(
    badTerminal.send("preflight/b", async () => 200),
    /journal/,
  );
});

test("admission requires every declared preflight check", async () => {
  const { value: rejected, events } = counter(["preflight/a", "preflight/b"]);
  await rejected.start({ runId: "run-c" });
  await rejected.sendPreflight(
    "preflight/a",
    async () => 404,
    (status) => status === 404,
  );
  await assert.rejects(
    rejected.send("subject/a", async () => 200),
    /preflight/,
  );
  assert.equal(rejected.snapshot().mode, "closed");
  assert.equal(events.at(-1)[1].outcome, "preflight-failed");

  const { value } = counter(["preflight/a", "preflight/b"]);
  await value.start({ runId: "run-c" });
  await value.sendPreflight(
    "preflight/a",
    async () => 404,
    (status) => status === 404,
  );
  assert.throws(() => value.admit(), /incomplete/);
  await value.sendPreflight(
    "preflight/b",
    async () => 200,
    (status) => status === 200,
  );
  value.admit();
  assert.equal(await value.send("subject/a", async () => 200), 200);
});

test("later mutation of the preflight ID input cannot weaken admission", async () => {
  const ids = ["preflight/a", "preflight/b"];
  const { value } = counter(ids);
  ids.pop();
  await value.start({ runId: "run-d" });
  await value.sendPreflight(
    "preflight/a",
    async () => 200,
    (status) => status === 200,
  );
  assert.throws(() => value.admit(), /incomplete/);
  await value.sendPreflight(
    "preflight/b",
    async () => 200,
    (status) => status === 200,
  );
  value.admit();
});

test("an asynchronous preflight verdict blocks concurrent preflight dispatch", async () => {
  const { value, events } = counter(["preflight/a", "preflight/b"]);
  await value.start({ runId: "run-e" });
  let rejectVerdict;
  const first = value.sendPreflight(
    "preflight/a",
    async () => 500,
    () =>
      new Promise((resolve) => {
        rejectVerdict = resolve;
      }),
  );
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(
    value.sendPreflight(
      "preflight/b",
      async () => 200,
      () => true,
    ),
    /concurrent/,
  );
  await assert.rejects(
    value.send("subject/early", async () => 200),
    /preflight/,
  );
  rejectVerdict(false);
  await assert.rejects(first, /preflight/);
  assert.equal(value.snapshot().mode, "closed");
  assert.deepEqual(
    events.map(([type]) => type),
    ["started", "reserve", "terminal"],
  );
});

async function admitted() {
  const ctx = counter();
  await ctx.value.start({ runId: "run-a" });
  await ctx.value.sendPreflight(
    "preflight/a",
    async () => 200,
    (status) => status === 200,
  );
  ctx.value.admit();
  return ctx;
}

test("a run stopped before any mutation closes as stopped-no-mutation only while still normal", async () => {
  const { value, events } = await admitted();
  await value.send("subject/read", async () => 200);
  await value.finish("stopped-no-mutation");
  assert.deepEqual(events.at(-1), [
    "terminal",
    { outcome: "stopped-no-mutation", requests: 2, normal: 2, recovery: 0, maxRequests: 6648 },
  ]);
  assert.equal(value.snapshot().mode, "closed");
});

test("stopped-no-mutation is refused once recovery has begun", async () => {
  const { value, events } = await admitted();
  value.enterRecovery();
  await value.send("recovery/read", async () => 200);
  await assert.rejects(value.finish("stopped-no-mutation"), /invalid terminal outcome/);
  assert.equal(events.filter(([type]) => type === "terminal").length, 0);
  assert.equal(value.snapshot().mode, "recovery");
});

test("stopped-no-mutation is also refused in recovery mode before any recovery request", async () => {
  const { value } = await admitted();
  value.enterRecovery();
  await assert.rejects(value.finish("stopped-no-mutation"), /invalid terminal outcome/);
  assert.equal(value.snapshot().mode, "recovery");
});

test("a recovered close needs recovery mode and at least one recovery request", async () => {
  const early = await admitted();
  await assert.rejects(early.value.finish("recovered"), /invalid terminal outcome/);
  const empty = await admitted();
  empty.value.enterRecovery();
  await assert.rejects(empty.value.finish("recovered"), /invalid terminal outcome/);
  const { value, events } = await admitted();
  await value.send("subject/write", async () => 200);
  value.enterRecovery();
  await value.send("recovery/delete", async () => 200);
  await value.finish("recovered");
  assert.deepEqual(events.at(-1), [
    "terminal",
    { outcome: "recovered", requests: 3, normal: 2, recovery: 1, maxRequests: 6648 },
  ]);
  assert.equal(value.snapshot().mode, "closed");
});

test("the existing finished and needs-recovery closes still work in either mode and unknown outcomes stay refused", async () => {
  const normal = await admitted();
  await normal.value.finish("finished");
  const recovering = await admitted();
  recovering.value.enterRecovery();
  await recovering.value.finish("needs-recovery");
  const other = await admitted();
  await assert.rejects(other.value.finish("stopped"), /invalid terminal outcome/);
});
