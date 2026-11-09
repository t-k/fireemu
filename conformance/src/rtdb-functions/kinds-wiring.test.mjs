import test from "node:test";
import assert from "node:assert/strict";
import { origin, listRequest, logFilter, parseEntries } from "./breadth-logs.mjs";
import { breadthCli, createBreadthBudget, createLogReader } from "./breadth-wiring.mjs";
import { FIXTURE_HANDLERS, FRAME_MARKER } from "./kinds-frames.mjs";
import {
  KINDS_CEILINGS,
  KINDS_LIMITS,
  KINDS_SCENARIO,
  KINDS_WINDOWS,
  rulesFor,
} from "./kinds-scenario.mjs";
import { TARGETS } from "./kinds-targets.mjs";

const handlers = FIXTURE_HANDLERS;

test("the log filter names every kinds handler origin and no breadth one", () => {
  const filter = logFilter({ start: "a", end: "b" }, handlers);
  for (const handler of handlers) {
    const o = origin(handler);
    assert.ok(
      filter.includes(
        `resource.labels.${Object.keys(o.labels)[0]}="${Object.values(o.labels)[0]}"`,
      ),
    );
  }
  assert.ok(!filter.includes("g9WrittenV2"));
  assert.match(filter, /G9_FRAME/);
  const request = listRequest({ start: "a", end: "b" }, handlers);
  // 2nd gen services are lower-cased in the log's resource labels
  assert.ok(request.body.filter.includes('service_name="k9createdv2"'));
  assert.ok(request.body.filter.includes('service_name="k9groupwrittenv2"'));
  assert.ok(request.body.filter.includes('function_name="k9CreatedV1"'));
});

const entryFor = (handler, extra = {}) => {
  const o = origin(handler);
  return {
    insertId: `${handler.name}-${Math.random()}`,
    logName: o.logName,
    resource: { type: o.resourceType, labels: o.labels },
    textPayload: `${FRAME_MARKER}${JSON.stringify({ handler: handler.name, generation: handler.generation })}`,
    ...extra,
  };
};

test("log parsing accepts the kinds handlers and drops a breadth handler as unknown", () => {
  const v1 = handlers.find((h) => h.name === "k9CreatedV1");
  const v2 = handlers.find((h) => h.name === "k9AnyWrittenV2");
  const breadth = { name: "g9WrittenV2", generation: 2 };
  const result = parseEntries(
    { entries: [entryFor(v1), entryFor(v2), entryFor(breadth)] },
    { readAt: "now", handlers },
  );
  assert.deepEqual(
    result.frames.map((f) => f.handler),
    ["k9CreatedV1", "k9AnyWrittenV2"],
  );
  assert.equal(result.ignored.unknownHandler, 1);
  // a kinds handler under the default (breadth) list is unknown, so the default is unchanged
  assert.equal(
    parseEntries({ entries: [entryFor(v1)] }, { readAt: "now" }).ignored.unknownHandler,
    1,
  );
  // a frame from the wrong origin is foreign
  const wrong = entryFor(v2, { logName: "other" });
  assert.equal(
    parseEntries({ entries: [wrong] }, { readAt: "now", handlers }).ignored.foreignOrigin,
    1,
  );
});

test("the log reader reads with the scenario's handlers", async () => {
  const seen = [];
  const reader = createLogReader({
    control: async (method, url, body) => {
      seen.push(body.filter);
      return { value: { entries: [entryFor(handlers[0])] } };
    },
    now: () => "now",
    handlers,
  });
  const reply = await reader.read({ start: "a", end: "b" });
  assert.equal(reply.frames.length, 1);
  assert.ok(seen[0].includes('service_name="k9createdv2"'));
});

test("the kinds CLI pins the kinds config and refuses other functions", async () => {
  const calls = [];
  const run = breadthCli(async (...args) => calls.push(args), KINDS_SCENARIO);
  for (const target of TARGETS) {
    const args = ["deploy", "--only", `functions:rtdb-kinds-oracle:${target.functionName}`];
    await run(args, "adc", "budget");
    assert.deepEqual(calls.at(-1)[0], [...args, "--config", "firebase-kinds.json", "--force"]);
  }
  for (const args of [
    ["deploy", "--only", "functions:rtdb-breadth-oracle:g9WrittenV2"],
    ["deploy", "--only", "functions:rtdb-kinds-oracle:other"],
    [
      "deploy",
      "--only",
      "functions:rtdb-kinds-oracle:k9CreatedV2",
      "--only",
      "functions:rtdb-kinds-oracle:k9CreatedV1",
    ],
    ["deploy", "--only", "functions:rtdb-kinds-oracle:k9CreatedV2", "--config", "x"],
    ["delete", "--only", "functions:rtdb-kinds-oracle:k9CreatedV2"],
  ])
    await assert.rejects(run(args, "adc", "budget"), /invalid breadth deploy/);
});

test("kinds targets are the planned eight, six required, in deploy order", () => {
  assert.deepEqual(
    TARGETS.map((t) => [t.functionName, t.required, t.generation]),
    [
      ["k9CreatedV2", true, "gcfv2"],
      ["k9UpdatedV2", true, "gcfv2"],
      ["k9DeletedV2", true, "gcfv2"],
      ["k9CreatedV1", true, "gcfv1"],
      ["k9UpdatedV1", true, "gcfv1"],
      ["k9DeletedV1", true, "gcfv1"],
      ["k9AnyWrittenV2", false, "gcfv2"],
      ["k9GroupWrittenV2", false, "gcfv2"],
    ],
  );
  assert.ok(TARGETS.every((t) => t.region === "us-central1"));
  assert.equal(new Set(TARGETS.map((t) => t.key)).size, 8);
});

test("the kinds limits scale the breadth ones to eight functions and are pinned", () => {
  assert.deepEqual(KINDS_LIMITS, {
    cliDeploy: 8,
    upload: 120,
    token: 12,
    control: 68,
    cleanup: 168,
    logs: 60,
    inventory: 100,
    userClient: 6,
    browserHttp: 80,
    browserWs: 4,
  });
  assert.deepEqual(KINDS_CEILINGS, { normal: 250, cleanup: 380 });
  assert.deepEqual(KINDS_WINDOWS, {
    propagationMs: 300000,
    writeMs: 6000,
    pollMs: 15000,
    quietMs: 30000,
    tailMs: 210000,
  });
});

test("the kinds budget enforces its own normal and cleanup ceilings", () => {
  const budget = createBreadthBudget(KINDS_SCENARIO);
  for (let i = 0; i < 200; i++) budget.take("rtdbAdmin");
  for (let i = 0; i < 50; i++) budget.take("breadthAuth");
  assert.throws(() => budget.take("control"), /250/);
  budget.startCleanup();
  for (let i = 0; i < 130; i++) budget.take("cleanup");
  assert.equal(budget.snapshot().total, 380);
  assert.throws(() => budget.take("cleanup"), /380/);
  // the default budget is still the breadth one
  const breadth = createBreadthBudget();
  for (let i = 0; i < 130; i++) breadth.take("rtdbAdmin");
  assert.throws(() => breadth.take("control"), /130/);
});

test("the kinds rules open only the user groups, write-guarded by auth and the run nonce", () => {
  const { rules } = rulesFor("k9-rtdb", "abc123");
  assert.equal(rules[".read"], false);
  assert.equal(rules[".write"], false);
  const guard = {
    ".write": "auth != null",
    ".validate": "newData.child('run').val() === 'abc123'",
  };
  assert.deepEqual(Object.keys(rules["k9-rtdb"]).toSorted(), ["gc", "gs"]);
  assert.deepEqual(rules["k9-rtdb"].gc, { items: { $id: guard } });
  // the SDK group is also readable by the signed-in user: a transaction listens to its node and compares its
  // hash, which production answers with permission_denied (or a stale loop) when the user may not read it
  assert.deepEqual(rules["k9-rtdb"].gs, { items: { $id: { ".read": "auth != null", ...guard } } });
  assert.throws(() => rulesFor("k9-rtdb", "bad nonce"), /invalid nonce/);
});
