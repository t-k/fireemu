import assert from "node:assert/strict";
import test from "node:test";
import { createLedger, kindOf } from "./pubsub-observation/ledger.mjs";
import { runCell } from "./pubsub-observation/scenarios.mjs";
import { makePlan, validatePlan, categoryCaps } from "./pubsub-observation/plan.mjs";

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

test("Task24 each recorder closes journals and listeners after reporting and wire-close failures", async () => {
  const family = process.env.OBSERVATION_PACKET ?? "A";
  const namespace =
    family === "A" ? "pubsub-observation" : `pubsub-observation-${family.toLowerCase()}`;
  const { main } = await import(`./${namespace}/record.mjs`);
  const { EventEmitter } = await import("node:events");
  const out = tempDir("pubsub-run-finalizer-"),
    signals = new EventEmitter(),
    w = world({ dispatchFailure: true });
  let savedJournal, exitCode;
  const values = {
    authority: "fixture",
    descriptor: "fixture",
    packet: "fixture",
    E: "fixture",
    V: "fixture",
    lock: "fixture",
    "run-id": runId,
    out,
  };
  const summary = await main(
    ["--record", ...Object.entries(values).flatMap(([key, value]) => [`--${key}`, value])],
    {
      admit: () => ({
        plan: makePlan(),
        check() {},
        descriptor: { head: "a".repeat(40) },
        descriptorSha256: "b".repeat(64),
        scope: { envelopeId: "FIXTURE", packetSha256: "c".repeat(64) },
      }),
      createCredentials: () => async () => "fixture-token",
      signals,
      setExitCode: (code) => {
        exitCode = code;
      },
      createWire({ journal }) {
        savedJournal = journal;
        const write = journal.write;
        journal.write = (row) => {
          if (
            row.event === "case-incomplete" ||
            row.stage === "case-incomplete" ||
            row.event === "run-incomplete"
          )
            throw new Error("reporting refused");
          write(row);
        };
        return {
          ...w.wire,
          close() {
            throw new Error("wire close refused");
          },
          async open() {
            throw new Error("stream refused");
          },
        };
      },
    },
  );
  assert.equal(summary.recordingComplete, false);
  assert.equal(summary.resourcesClosed, false);
  assert.equal(exitCode, 2);
  assert.equal(signals.listenerCount("SIGINT"), 0);
  assert.equal(signals.listenerCount("SIGTERM"), 0);
  assert.throws(() => savedJournal.write({ event: "late" }), /closed journal/);
  const recovery = readFileSync(join(out, `recovery-${runId}.jsonl`), "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse);
  assert.ok(recovery.some((row) => row.event === "recovery-binding"));
  assert.ok(Array.isArray(recovery.at(-1).obligations));
  assert.ok(w.calls.some((call) => call.method === "DeleteTopic"));
});

test("Task24 each packet never treats unknown NOT_FOUND as permission to suppress confirmed cleanup", async () => {
  const family = process.env.OBSERVATION_PACKET ?? "A";
  const namespace =
    family === "A" ? "pubsub-observation" : `pubsub-observation-${family.toLowerCase()}`;
  const { makePlan: familyPlan } = await import(`./${namespace}/plan.mjs`);
  const { runCell: familyRun } = await import(`./${namespace}/scenarios.mjs`);
  const cell = familyPlan().cells.find((c) => !c.reserve && c.group !== "G4"),
    w = world();
  const original = w.wire.call;
  let injectedName;
  w.wire.call = async (call) => {
    if (
      !injectedName &&
      call.method === "GetTopic" &&
      !call.category.startsWith("cleanup") &&
      w.resources.has(call.request.name)
    ) {
      injectedName = call.request.name;
      return {
        ok: false,
        status: 418,
        code: "NOT_FOUND",
        unknown: false,
        body: { error: { status: "NOT_FOUND" } },
      };
    }
    return original(call);
  };
  const result = await familyRun({
    cell,
    meter,
    ledger: createLedger(),
    runId,
    wire: w.wire,
    journal: w.journal,
    sleep: async () => {},
    iamJournal: { write() {} },
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true, family);
  assert.ok(injectedName, `post-CREATE stimulus reached: ${family}`);
  assert.equal(
    w.calls.filter((c) => c.method === "DeleteTopic" && c.request.name === injectedName).length,
    1,
    family,
  );
  assert.equal(w.resources.size, 0, family);
});

const gapSelections = [
  ["valid-stream-gap", ["S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09"]],
  ["invalid-path-gap", ["S12", "S13", "S14", "S15", "R1", "R2"]],
];

test("fixed gap selections retain exact original cells, ordering and unchanged ceilings", () => {
  const full = makePlan();
  for (const [selection, ids] of gapSelections) {
    const plan = makePlan(selection);
    assert.deepEqual(
      plan.cells.map((cell) => cell.id),
      ids,
    );
    assert.deepEqual(
      plan.cells,
      ids.map((id) => full.cells.find((cell) => cell.id === id)),
    );
    assert.deepEqual(
      {
        ...plan,
        cells: full.cells,
        caps: full.caps,
        recordings: full.recordings,
        selection: undefined,
      },
      { ...full, selection: undefined },
    );
    assert.equal(validatePlan(plan), plan);
    assert.equal(
      plan.cells.some((cell) => cell.reserve),
      false,
    );
    assert.equal(
      plan.cells.some((cell) => ["S10", "S11", "S16"].includes(cell.id)),
      false,
    );
    assert.equal(
      plan.cells.some((cell) => /^(request|message)-/.test(cell.variant)),
      false,
    );
  }
});

test("gap admission refuses near selections and any edited cell, order, cap or policy", () => {
  for (const selection of [
    "S01",
    "S01-S09",
    "valid-stream-gap-extra",
    "invalid-path-gap-extra",
    "gap",
    ["S01"],
    { cells: ["S01"] },
  ])
    assert.throws(() => makePlan(selection), /fixed observation selection/);
  for (const [selection] of gapSelections)
    for (const mutate of [
      (plan) => (plan.cells = plan.cells.toReversed()),
      (plan) => plan.cells.pop(),
      (plan) => plan.cells.push(makePlan().cells.find((cell) => cell.id === "S10")),
      (plan) => (plan.cells[0].variant = "invalid-ack-silence"),
      (plan) => (plan.cells[0].reserve = true),
      (plan) => plan.caps.totalRequests++,
      (plan) => plan.caps.framesIn++,
      (plan) => plan.streamWindowMs++,
      (plan) => plan.recordings++,
      (plan) => (plan.ackSelector = "MATCH"),
      (plan) => (plan.a2.minAgeMs = 0),
      (plan) => plan.timeoutPolicy.otherMs++,
    ]) {
      const edited = structuredClone(makePlan(selection));
      mutate(edited);
      assert.throws(() => validatePlan(edited), /fixed observation plan mismatch/);
    }
  assert.equal(makePlan().cells.length, 37);
  assert.deepEqual(
    makePlan("s10-diagnostic").cells.map((cell) => cell.id),
    ["S10"],
  );
  assert.equal(makePlan("residual").cells.length, 22);
});

test("selected path-body cells retain unknown refusal before target dispatch", async () => {
  for (const id of ["R1", "R2"]) {
    const w = world();
    const call = w.wire.call;
    let unknownSent = false;
    w.wire.call = async (request) => {
      if (!unknownSent && request.category === "get") {
        unknownSent = true;
        w.calls.push(request);
        return { ok: false, status: 418, code: "UNKNOWN", unknown: false, body: {} };
      }
      return call(request);
    };
    const result = await runCell({
      cell: makePlan("invalid-path-gap").cells.find((cell) => cell.id === id),
      meter,
      ledger: createLedger(),
      runId,
      ...w,
    });
    assert.equal(unknownSent, true);
    assert.equal(result.complete, false);
    assert.equal(
      w.calls.some((request) => request.category === "target"),
      false,
    );
  }
});

test("fixed gap reachability bounds existing categories and native frame slots without large publications", () => {
  const projections = gapSelections.map(([selection]) => {
    const plan = makePlan(selection);
    const starts = plan.cells.reduce(
      (sum, cell) =>
        sum + Object.values(categoryCaps(cell.group)).reduce((total, cap) => total + cap, 0),
      plan.caps.G7.requests,
    );
    const streams = plan.cells.filter((cell) => cell.group === "G4").length;
    assert.ok(starts <= plan.caps.totalRequests);
    assert.ok(streams <= plan.caps.G4.streams);
    assert.ok(streams * 6 <= plan.caps.framesOut);
    assert.ok(streams * 6 <= plan.caps.framesIn);
    assert.equal(
      plan.cells.some((cell) => /^(request|message)-/.test(cell.variant)),
      false,
    );
    return { starts, streams, smallPublishes: streams * categoryCaps("G4").publish };
  });
  assert.deepEqual(projections, [
    { starts: 176, streams: 9, smallPublishes: 27 },
    { starts: 110, streams: 4, smallPublishes: 12 },
  ]);
  assert.equal(projections[1].starts * 2, 220);
});

test("existing packet and scope admission bind each fixed gap plan while retaining two reserved namespaces", async () => {
  const { verifyScope, verifyPacket } = await import("./pubsub-observation/admission.mjs");
  const { isRecordingComplete } = await import("./pubsub-observation/record.mjs");
  for (const [selection] of gapSelections) {
    const plan = makePlan(selection),
      runIds = ["012345abcdef", "abcdef012345"].slice(0, plan.recordings),
      descriptor = { head: "a".repeat(40) },
      digest = "b".repeat(64);
    const scope = {
      taskId: "PUBSUB-OBSERVATION-A",
      suite: plan.suite,
      project: plan.project,
      envelopeId: "GAP-FIXTURE",
      sourceHead: descriptor.head,
      descriptorSha256: digest,
      packetSha256: "c".repeat(64),
      runIds,
      runOutputs: Object.fromEntries(runIds.map((id) => [id, `/fixture/run-${id}`])),
      recoveryOutputs: Object.fromEntries(runIds.map((id) => [id, `/fixture/recovery-${id}`])),
      expiresAt: new Date(2000).toISOString(),
      plan,
    };
    const packet = {
      sha256: scope.packetSha256,
      value: {
        schema: 1,
        taskId: scope.taskId,
        version: "v1",
        sourceHead: descriptor.head,
        descriptorSha256: digest,
        runIds,
        runOutputs: scope.runOutputs,
        recoveryOutputs: scope.recoveryOutputs,
        plan,
      },
    };
    assert.equal(verifyPacket(packet, scope, descriptor, digest), plan);
    assert.doesNotThrow(() =>
      verifyScope(
        scope,
        descriptor,
        digest,
        { runId: runIds[0], out: scope.runOutputs[runIds[0]] },
        1000,
      ),
    );
    assert.equal(
      isRecordingComplete(
        plan,
        plan.cells.map((cell) => ({ cellId: cell.id, complete: true })),
      ),
      true,
    );
    assert.throws(
      () =>
        verifyScope(
          { ...scope, runIds: ["012345abcdef", "abcdef012345", "fedcba012345"] },
          descriptor,
          digest,
          { runId: runIds[0], out: scope.runOutputs[runIds[0]] },
          1000,
        ),
      /source-bound scope mismatch/,
    );
    assert.throws(
      () =>
        verifyPacket(
          { ...packet, value: { ...packet.value, plan: makePlan("residual") } },
          scope,
          descriptor,
          digest,
        ),
      /packet identity mismatch/,
    );
  }
});

test("gap plans bind closed execution counts and category-derived call, frame and publication caps", () => {
  for (const [selection, expected] of [
    [
      "valid-stream-gap",
      {
        recordings: 1,
        sourceRequests: 162,
        totalRequests: 176,
        frames: 54,
        smallPublishes: 27,
        sourceWallMs: 1620000,
        g4: { requests: 162, rest: 153, grpc: 0, streams: 9 },
        g1: { requests: 0, rest: 0, grpc: 0, streams: 0 },
      },
    ],
    [
      "invalid-path-gap",
      {
        recordings: 2,
        sourceRequests: 96,
        totalRequests: 110,
        frames: 24,
        smallPublishes: 12,
        sourceWallMs: 960000,
        g4: { requests: 72, rest: 68, grpc: 0, streams: 4 },
        g1: { requests: 24, rest: 24, grpc: 0, streams: 0 },
      },
    ],
  ]) {
    const plan = makePlan(selection),
      caps = plan.caps;
    assert.equal(plan.recordings, expected.recordings);
    for (const field of ["sourceRequests", "totalRequests", "smallPublishes", "sourceWallMs"])
      assert.equal(caps[field], expected[field]);
    assert.equal(caps.framesOut, expected.frames);
    assert.equal(caps.framesIn, expected.frames);
    assert.equal(caps.largePublishes, 0);
    assert.deepEqual(caps.G4, { ...expected.g4, cellMs: 180000 });
    assert.deepEqual(caps.G1, { ...expected.g1, cellMs: 120000 });
    assert.deepEqual(caps.G7, makePlan().caps.G7);
    for (const field of [
      "frameBytes",
      "metadataBytesEachDirection",
      "largeEncodedPayloadBytes",
      "smallEncodedPayloadBytes",
      "cleanupReserveMs",
    ])
      assert.equal(caps[field], makePlan().caps[field]);
  }
});

test("actual admitted gap plan reaches the existing meter and refuses extra namespaces and cells", async () => {
  const admission = await import("./pubsub-observation/admission.mjs");
  const { sha256 } = await import("./pubsub-production/admission.mjs");
  const { dirname, resolve } = await import("node:path");
  for (const [selection] of gapSelections) {
    const plan = makePlan(selection),
      ids = ["012345abcdef", "abcdef012345"].slice(0, plan.recordings);
    const descriptor = { head: "a".repeat(40), sources: [] },
      digest = "b".repeat(64);
    const scope = {
      taskId: "PUBSUB-OBSERVATION-A",
      suite: plan.suite,
      project: plan.project,
      envelopeId: "GAP-FIXTURE",
      sourceHead: descriptor.head,
      descriptorSha256: digest,
      packetSha256: "c".repeat(64),
      runIds: ids,
      runOutputs: Object.fromEntries(ids.map((id) => [id, `/fixture/run-${id}`])),
      recoveryOutputs: Object.fromEntries(ids.map((id) => [id, `/fixture/recovery-${id}`])),
      expiresAt: "2099-01-01T00:00:00Z",
      plan,
    };
    const files = {
      descriptor: { value: descriptor, sha256: digest },
      authority: { value: scope },
      packet: {
        sha256: scope.packetSha256,
        value: {
          schema: 1,
          taskId: scope.taskId,
          version: "v1",
          sourceHead: descriptor.head,
          descriptorSha256: digest,
          runIds: ids,
          runOutputs: scope.runOutputs,
          recoveryOutputs: scope.recoveryOutputs,
          plan,
        },
      },
    };
    const lines = [];
    for (const kind of ["E", "V"]) {
      const row = { ...scope, kind, state: "APPROVED", ledgerLine: lines.length + 1 };
      const line = `| ${kind === "E" ? "PUBSUB-OBSERVATION-A envelope" : "PUBSUB-OBSERVATION-A"} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${admission.scopeDigest(row)} |`;
      lines.push(line);
      row.ledgerLineSha256 = sha256(line);
      files[kind] = { value: row, sha256: (kind === "E" ? "e" : "f").repeat(64) };
      scope[kind] = { sha256: files[kind].sha256 };
    }
    const boundary = {
      readJson: (path) => files[path],
      verifyDescriptor() {},
      verifyScope: admission.verifyScope,
      verifyPacket: admission.verifyPacket,
      dirname,
      git: (...args) =>
        args[0] === "rev-parse" && args[1] === "HEAD" ? descriptor.head : "/fixture/.git",
      resolve,
      readFileSync: () => lines.join("\n"),
      sha256,
      verifyProof: admission.verifyProof,
      PROJECT: plan.project,
      verifyLiveLock() {},
      unusedRunPreflight: () => ({ unused: true }),
    };
    // Retain the actual admission body; substitute only external source, file and authority boundaries.
    const admit = new Function(...Object.keys(boundary), `return (${admission.admit.toString()});`)(
      ...Object.values(boundary),
    );
    const options = {
      descriptor: "descriptor",
      authority: "authority",
      packet: "packet",
      E: "E",
      V: "V",
      lock: "/fixture/lock",
      runId: ids[0],
      out: scope.runOutputs[ids[0]],
    };
    const admitted = admit(options, 1000);
    assert.equal(admitted.plan, plan);
    const selectedMeter = createMeter({ plan: admitted.plan, now: () => 0 });
    assert.throws(
      () => selectedMeter.enter(makePlan().cells.find((cell) => cell.id === "S10")),
      /undeclared cell/,
    );
    selectedMeter.enter(plan.cells[0]);
    selectedMeter.start("create", "rest");
    assert.equal(selectedMeter.snapshot().requests, 1);
    const { main } = await import("./pubsub-observation/record.mjs");
    const { EventEmitter } = await import("node:events");
    const out = tempDir("pubsub-gap-meter-"),
      signals = new EventEmitter(),
      w = world({ dispatchFailure: true });
    let meterChecked = false;
    const values = {
      authority: "fixture",
      descriptor: "fixture",
      packet: "fixture",
      E: "fixture",
      V: "fixture",
      lock: "fixture",
      "run-id": ids[0],
      out,
    };
    const summary = await main(
      ["--record", ...Object.entries(values).flatMap(([key, value]) => [`--${key}`, value])],
      {
        admit: () => admitted,
        createCredentials: () => async () => "fixture-token",
        signals,
        setExitCode() {},
        createWire({ meter: actualMeter }) {
          assert.throws(
            () => actualMeter.enter(makePlan().cells.find((cell) => cell.id === "S10")),
            /undeclared cell/,
          );
          meterChecked = true;
          return { ...w.wire, close() {} };
        },
      },
    );
    assert.equal(meterChecked, true);
    assert.equal(summary.recordingComplete, false);
    assert.equal(summary.results[0].cellId, plan.cells[0].id);
    assert.equal(signals.listenerCount("SIGINT"), 0);
    assert.throws(
      () => admit({ ...options, runId: "fedcba012345", out: "/fixture/foreign" }, 1000),
      /source-bound scope mismatch/,
    );
    if (plan.recordings === 1)
      assert.throws(
        () => admit({ ...options, runId: "abcdef012345", out: "/fixture/run-abcdef012345" }, 1000),
        /source-bound scope mismatch/,
      );
    else
      assert.throws(
        () => admit({ ...options, runId: ids[1], out: scope.runOutputs[ids[1]] }, 1000),
        /run2 prior summary path mismatch/,
      );
    const edited = structuredClone(plan);
    edited.caps.totalRequests++;
    assert.throws(() => createMeter({ plan: edited }), /fixed observation plan mismatch/);
    if (selection === "invalid-path-gap") {
      const payloadMeter = createMeter({ plan, now: () => 0 });
      payloadMeter.enter(plan.cells.find((cell) => cell.id === "R1"));
      assert.throws(() => payloadMeter.payload(1), /publish payload cap/);
    }
  }
});
