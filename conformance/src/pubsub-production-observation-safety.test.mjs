import assert from "node:assert/strict";
import test from "node:test";
import { createLedger, kindOf } from "./pubsub-observation/ledger.mjs";
import { runCell } from "./pubsub-observation/scenarios.mjs";
import { makePlan } from "./pubsub-observation/plan.mjs";

function world({ dispatchFailure = false, reportingFailure = false, updates418 = false } = {}) {
  const resources = new Map(),
    calls = [],
    rows = [];
  const journal = {
    write(row) {
      if (reportingFailure && (row.event === "case-incomplete" || row.stage === "case-incomplete"))
        throw new Error("report refused");
      rows.push(row);
    },
  };
  const wire = {
    async call(call) {
      calls.push(call);
      const name = call.request.name ?? call.request.subscription?.name;
      if (call.method === "CreateSubscription" && dispatchFailure)
        throw new Error("dispatch refused");
      if (call.method.startsWith("Create")) {
        resources.set(name, { ...call.request });
        return { ok: true, code: "OK", body: resources.get(name) };
      }
      if (call.method.startsWith("Delete")) {
        resources.delete(name);
        return { ok: true, code: "OK", body: {} };
      }
      if (call.method.startsWith("Get"))
        return resources.has(name)
          ? { ok: true, code: "OK", body: resources.get(name) }
          : { ok: false, status: 404, code: "NOT_FOUND", body: { error: { status: "NOT_FOUND" } } };
      if (call.method === "UpdateSubscription" && updates418)
        return { ok: false, status: 418, code: "UNKNOWN", unknown: false, body: {} };
      return { ok: true, code: "OK", body: {} };
    },
  };
  return { resources, calls, rows, journal, wire };
}
const meter = {
  remaining() {
    return 180000;
  },
  clock() {
    return 0;
  },
};
const runId = "123456abcdef";

test("Task24 R3 stops at the first unexpected update instead of accepting both 418 replies", async () => {
  const w = world({ updates418: true });
  const result = await runCell({
    cell: makePlan().cells.find((c) => c.id === "R3"),
    meter,
    ledger: createLedger(),
    runId,
    ...w,
  });
  assert.equal(w.calls.filter((c) => c.method === "UpdateSubscription").length, 1);
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
  assert.equal(w.resources.size, 0);
});

test("Task24 successful topic CREATE is cleaned despite dispatch and reporting failures", async () => {
  const w = world({ dispatchFailure: true, reportingFailure: true });
  let failure;
  try {
    await runCell({
      cell: makePlan().cells.find((c) => c.id === "R3"),
      meter,
      ledger: createLedger(),
      runId,
      ...w,
    });
  } catch (error) {
    failure = error;
  }
  assert.equal(w.calls.filter((c) => c.method === "DeleteTopic").length, 1, failure?.message);
  assert.equal([...w.resources.keys()].filter((n) => n.includes("/topics/")).length, 0);
});

test("Task24 known status/code pairs reject contradictory and unlisted answers at the ledger boundary", () => {
  for (const [status, code, ok] of [
    [418, "UNKNOWN", false],
    [404, "INVALID_ARGUMENT", false],
    [400, "NOT_FOUND", false],
    [200, "NOT_FOUND", true],
    [409, "OK", false],
  ])
    assert.equal(kindOf({ status, code, ok, unknown: false, body: {} }), "unknown");
  assert.equal(kindOf({ ok: true, status: 200, code: "OK", body: {} }), "ok");
  assert.equal(
    kindOf({ ok: false, status: 404, code: "NOT_FOUND", body: { error: { status: "NOT_FOUND" } } }),
    "error",
  );
});

const { createWire } = await import("./pubsub-observation/wire.mjs");
const { createMeter } = await import("./pubsub-observation/meter.mjs");
const { createJournal } = await import("./pubsub-observation/journal.mjs");
const { normalizeOutcome } = await import("./pubsub-production/outcome.mjs");
const { protectCell, obligations, unusedRunPreflight } =
  await import("./pubsub-observation/safety.mjs");
const { tempDir } = await import("./test-tmpdir.mjs");
const { readFileSync, writeFileSync, mkdirSync } = await import("node:fs");
const { join } = await import("node:path");

test("Task24 raw REST 418 is captured unknown, stops later source calls and permits cleanup", async () => {
  const m = createMeter({ now: () => 0 }),
    rows = [];
  m.enter(makePlan().cells.find((c) => c.id === "R3"));
  let dispatches = 0;
  const wire = createWire({
    meter: m,
    journal: {
      write(row) {
        rows.push(row);
      },
    },
    getToken: async () => "fixture-token",
    client: { close() {} },
    fetch: async () => {
      dispatches++;
      return new Response("{}", { status: dispatches === 1 ? 418 : 200 });
    },
  });
  const call = {
    category: "target",
    transport: "rest",
    service: "Subscriber",
    method: "UpdateSubscription",
    cellId: "R3",
    request: {
      subscription: {
        name: "projects/fixture-project/subscriptions/fe123456abcdef-r3-sub",
        labels: {},
      },
      updateMask: "labels",
    },
  };
  try {
    const reply = await wire.call(call);
    assert.equal(reply.unknown, true);
    assert.equal(reply.status, 418);
    assert.equal(rows.find((r) => r.event === "response").reply.unknown, true);
    await assert.rejects(wire.call({ ...call, cellId: "R4" }), /source stopped/);
    assert.equal(dispatches, 1);
    await wire.call({
      ...call,
      category: "cleanupDelete",
      method: "DeleteSubscription",
      request: { name: call.request.subscription.name },
    });
    assert.equal(dispatches, 2);
  } finally {
    wire.close();
  }
});

test("Task24 finalizer cannot be bypassed by report or disposal and persists after cleanup failure", async () => {
  for (const reportFails of [false, true])
    for (const disposeFails of [false, true]) {
      const order = [];
      const failures = await protectCell({
        body() {
          order.push("body");
          throw new Error("dispatch");
        },
        report() {
          order.push("report");
          if (reportFails) throw new Error("report");
        },
        dispose() {
          order.push("dispose");
          if (disposeFails) throw new Error("dispose");
        },
        finalize() {
          order.push("cleanup");
          throw new Error("cleanup");
        },
        persist() {
          order.push("persist");
        },
      });
      assert.deepEqual(order, ["body", "report", "dispose", "cleanup", "persist"]);
      assert.equal(failures.length, 2 + Number(reportFails) + Number(disposeFails));
    }
});

test("Task24 independent durable recovery retains confirmed CREATE when cleanup dispatch refuses", async () => {
  const out = tempDir("pubsub-safety-"),
    journal = createJournal(out, runId),
    ledger = createLedger();
  const w = world({ dispatchFailure: true });
  const call = w.wire.call;
  w.wire.call = async (value) => {
    if (value.method === "DeleteTopic") throw new Error("cleanup refused");
    return call(value);
  };
  const write = journal.write;
  journal.write = (row) => {
    if (row.event === "case-incomplete") throw new Error("capture refused");
    write(row);
  };
  let result;
  try {
    result = await runCell({
      cell: makePlan().cells.find((c) => c.id === "R3"),
      meter,
      ledger,
      runId,
      wire: w.wire,
      journal,
    });
  } finally {
    journal.close();
  }
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, false);
  const rows = readFileSync(join(out, `recovery-${runId}.jsonl`), "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse);
  assert.ok(
    rows.some((r) =>
      r.obligations.some(
        (o) => o.name.endsWith("-topic") && o.intents.some((i) => i.action === "create"),
      ),
    ),
  );
  const last = rows.at(-1).obligations;
  assert.ok(
    last.some(
      (o) =>
        o.name.endsWith("-topic") &&
        o.requests.some((r) => r.action === "create" && r.resolution === "confirmed"),
    ),
  );
  assert.ok(last.every((o) => typeof o.name === "string"));
});

test("Task24 recovery inventory agrees with a per-resource reference model over generated histories", () => {
  for (let seed = 1; seed <= 128; seed++) {
    const l = createLedger(),
      names = new Set(),
      reference = new Set();
    for (let index = 0; index < 4; index++) {
      const name = `projects/fixture-project/topics/fe123456abcdef-${index}`;
      names.add(name);
      const id = l.sent({ name, action: "create", transport: "rest" });
      const kind = (seed >> index) & 1 ? "ok" : "error";
      l.answered({ name, action: "create", transport: "rest", requestId: id, kind });
      if (kind === "ok") reference.add(name);
    }
    assert.deepEqual(new Set(obligations(l, names).map((o) => o.name)), reference);
  }
});

test("Task24 finite outcome matrix preserves known pairs and uncertainty for every near miss", () => {
  const pairs = [
    [400, "INVALID_ARGUMENT"],
    [400, "FAILED_PRECONDITION"],
    [400, "OUT_OF_RANGE"],
    [401, "UNAUTHENTICATED"],
    [403, "PERMISSION_DENIED"],
    [404, "NOT_FOUND"],
    [409, "ALREADY_EXISTS"],
    [409, "ABORTED"],
    [429, "RESOURCE_EXHAUSTED"],
  ];
  for (const [status, code] of pairs) {
    const reply = { ok: false, status, code, body: { error: { status: code, code: status } } };
    assert.equal(normalizeOutcome(reply).unknown, false);
    for (const mutant of [
      { ...reply, ok: true },
      { ...reply, status: status + 1 },
      { ...reply, code: "FOREIGN" },
      { ...reply, body: {} },
      { ...reply, unknown: true },
    ])
      assert.equal(normalizeOutcome(mutant).unknown, true);
  }
  for (const code of [
    "UNKNOWN",
    "CANCELLED",
    "UNAVAILABLE",
    "DEADLINE_EXCEEDED",
    "RESOURCE_EXHAUSTED",
  ])
    assert.equal(normalizeOutcome({ ok: false, code, body: {} }).unknown, true);
});

test("Task24 unused nonce preflight binds read-only ledger and directory facts and refuses reuse", () => {
  const root = tempDir("pubsub-nonce-"),
    ledgerPath = join(root, "ledger.jsonl"),
    runsRoot = join(root, "runs"),
    out = join(runsRoot, "new-output");
  mkdirSync(runsRoot);
  writeFileSync(ledgerPath, '{"runId":"abcdef012345"}\n');
  const options = { runId, out, ledgerPath, runsRoot };
  const receipt = unusedRunPreflight(options);
  assert.equal(receipt.unused, true);
  assert.match(receipt.ledgerSha256, /^[a-f0-9]{64}$/);
  writeFileSync(ledgerPath, `${JSON.stringify({ runId })}\n`);
  assert.throws(() => unusedRunPreflight(options), /already in ledger/);
  writeFileSync(ledgerPath, "");
  mkdirSync(join(runsRoot, `prior-${runId}`));
  assert.throws(() => unusedRunPreflight(options), /already used/);
});

test("Task24 each selected packet cleans confirmed setup after dispatch and reporting failure", async () => {
  const family = process.env.OBSERVATION_PACKET ?? "A";
  const namespace =
    family === "A" ? "pubsub-observation" : `pubsub-observation-${family.toLowerCase()}`;
  const { makePlan: familyPlan } = await import(`./${namespace}/plan.mjs`);
  const { runCell: familyRun } = await import(`./${namespace}/scenarios.mjs`);
  const cell = familyPlan().cells.find((c) => !c.reserve),
    w = world({ reportingFailure: true });
  let creates = 0;
  const original = w.wire.call;
  w.wire.call = (value) => {
    if (value.method.startsWith("Create") && ++creates === 2)
      throw new Error("second dispatch refused");
    return original(value);
  };
  let failure;
  try {
    await familyRun({
      cell,
      meter,
      ledger: createLedger(),
      runId,
      wire: w.wire,
      journal: w.journal,
      sleep: async () => {},
      iamJournal: { write() {} },
      serviceAgent: "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com",
    });
  } catch (error) {
    failure = error;
  }
  assert.equal(
    w.calls.filter((c) => c.method === "DeleteTopic").length,
    1,
    `${family}: ${failure?.message}`,
  );
  assert.equal([...w.resources.keys()].filter((n) => n.includes("/topics/")).length, 0);
});

test("Task24 recovery write-ahead failure prevents mutation while acquisition closes earlier handles", async () => {
  const w = world(),
    l = createLedger();
  w.journal.recovery = () => {
    throw new Error("durable intent refused");
  };
  const result = await runCell({
    cell: makePlan().cells.find((c) => c.id === "R3"),
    meter,
    ledger: l,
    runId,
    ...w,
  });
  assert.equal(result.complete, false);
  assert.equal(w.calls.length, 0);
  const { acquireResources } = await import("./pubsub-observation/safety.mjs");
  const closed = [];
  assert.throws(
    () =>
      acquireResources((register) => {
        register(() => {
          closed.push("capture");
          throw new Error("close");
        });
        register(() => closed.push("issued"));
        throw new Error("acquisition");
      }),
    /acquisition/,
  );
  assert.deepEqual(closed, ["issued", "capture"]);
});

test("Task24 the guarded ledger refuses contradictory positive and absence proofs", () => {
  const l = createLedger(),
    name = "projects/fixture-project/topics/fe123456abcdef-proof";
  const id = l.sent({ name, action: "create", transport: "rest" });
  l.answered({ name, action: "create", transport: "rest", requestId: id, kind: "unknown" });
  assert.equal(
    l.observeRead(name, { ok: true, status: 404, code: "NOT_FOUND", body: { name } }),
    false,
  );
  assert.equal(l.unconfirmed(name), true);
  assert.equal(l.observeRead(name, { ok: true, status: 200, code: "OK", body: { name } }), true);
  const d = l.sent({ name, action: "delete", transport: "rest" });
  l.answered({ name, action: "delete", transport: "rest", requestId: d, kind: "ok" });
  const absence = {
    ok: false,
    status: 404,
    code: "NOT_FOUND",
    body: { error: { status: "NOT_FOUND" } },
  };
  assert.equal(l.settleAbsent(name, { ...absence, ok: true }), false);
  assert.equal(l.settleAbsent(name, absence), true);
});

test("Task24 actual A cell cleanup runs even when stream dispose throws", async () => {
  const w = world();
  w.wire.open = async () => ({
    write() {},
    async next() {
      return null;
    },
    state() {
      return { incomplete: false, terminal: { code: "INVALID_ARGUMENT" } };
    },
    dispose() {
      throw new Error("dispose refused");
    },
  });
  const result = await runCell({
    cell: makePlan().cells.find((c) => c.variant === "missing-opening-subscription"),
    meter,
    ledger: createLedger(),
    runId,
    ...w,
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
  assert.equal(w.calls.filter((c) => c.method.startsWith("Delete")).length, 2);
});

test("Task24 each selected wire captures unexpected replies and refuses later source dispatch", async () => {
  const family = process.env.OBSERVATION_PACKET ?? "A";
  const namespace =
    family === "A" ? "pubsub-observation" : `pubsub-observation-${family.toLowerCase()}`;
  const { createWire: familyWire } = await import(`./${namespace}/wire.mjs`);
  const rows = [];
  let calls = 0;
  const wire = familyWire({
    meter: { ...meter, start() {}, payload() {} },
    journal: {
      write(row) {
        rows.push(row);
      },
    },
    getToken: async () => "fixture-token",
    client: { close() {} },
    fetch: async () => {
      calls++;
      return new Response("{}", { status: 418 });
    },
  });
  const call = {
    cellId: "fixture",
    category: "get",
    transport: "rest",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture-project/topics/fe123456abcdef-target" },
  };
  try {
    const reply = await wire.call(call);
    assert.equal(reply.unknown, true, family);
    assert.equal(rows.find((r) => r.event === "response").reply.unknown, true, family);
    await assert.rejects(wire.call({ ...call, cellId: "later" }), /source stopped/);
    assert.equal(calls, 1, family);
  } finally {
    wire.close();
  }
});

test("Task24 final recovery persistence failure is explicit and cannot be labelled closed", async () => {
  const failures = await protectCell({
    body() {},
    report() {},
    finalize() {},
    persist() {
      throw new Error("recovery persistence refused");
    },
  });
  assert.equal(failures.persistenceFailed, true);
  assert.equal(failures.length, 1);
});
