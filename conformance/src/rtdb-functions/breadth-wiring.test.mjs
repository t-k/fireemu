import test from "node:test";
import assert from "node:assert/strict";
import { BREADTH_LIMITS, createBreadthBudget } from "./breadth-wiring.mjs";

test("T1 request limits are pinned for three functions", () => {
  assert.deepEqual(BREADTH_LIMITS, {
    cliDeploy: 3,
    upload: 45,
    token: 12,
    control: 38,
    cleanup: 89,
    logs: 40,
    inventory: 100,
    userClient: 6,
    browserHttp: 40,
    browserWs: 4,
  });
});

test("shared budget enforces the normal and cleanup total boundaries", () => {
  const budget = createBreadthBudget();
  for (let i = 0; i < 200; i++) budget.take("rtdbAdmin");
  assert.equal(budget.snapshot().total, 200);
  assert.throws(() => budget.take("control"), /200/);
  budget.startCleanup();
  budget.take("cleanup");
  assert.equal(budget.snapshot().total, 201);
  for (let i = 0; i < 11; i++) budget.take("cleanup");
  assert.equal(budget.snapshot().total, 212);
  assert.throws(() => budget.take("cleanup"), /212/);
  assert.equal(budget.snapshot().total, 212);
});

test("breadth CLI pins force and config and rejects non-breadth commands", async () => {
  const { breadthCli } = await import("./breadth-wiring.mjs");
  const { TARGETS, CODEBASE } = await import("./breadth-targets.mjs");
  const calls = [];
  const run = breadthCli(async (...args) => calls.push(args));
  for (const target of TARGETS) {
    const args = ["deploy", "--only", `functions:${CODEBASE}:${target.functionName}`];
    await run(args, "adc", "budget");
    assert.deepEqual(calls.at(-1), [
      [...args, "--config", "firebase-breadth.json", "--force"],
      "adc",
      "budget",
    ]);
  }
  for (const args of [
    ["delete", "--only", `functions:${CODEBASE}:${TARGETS[0].functionName}`],
    ["deploy", "--only", "functions:foreign:other"],
    [
      "deploy",
      "--only",
      `functions:${CODEBASE}:${TARGETS[0].functionName}`,
      "--config",
      "other.json",
    ],
    [
      "deploy",
      "--only",
      `functions:${CODEBASE}:${TARGETS[0].functionName}`,
      "--only",
      "functions:other",
    ],
  ])
    await assert.rejects(run(args), /invalid breadth deploy/);
  assert.equal(calls.length, 3);
});

test("real source upload ledger admits and closes all three deploys", async () => {
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { openSourceUploads } = await import("../shared/gen2-source-uploads.mjs");
  const dir = await mkdtemp(join(tmpdir(), "breadth-uploads-"));
  const budget = createBreadthBudget();
  const uploads = openSourceUploads({
    ledgerPath: join(dir, "owned-uploads.jsonl"),
    runId: "test",
    projectNumber: "123456789012",
    region: "us-central1",
    requestsLeft: () => BREADTH_LIMITS.upload - budget.snapshot().upload,
    send: async () => {
      budget.take("upload");
      return { status: 200, bodyReadable: true, bytes: 2, value: { items: [] } };
    },
  });
  try {
    for (const key of ["F3", "F2", "F4"]) {
      const deploy = await uploads.beginDeploy(key, { generation: key === "F2" ? 1 : 2 });
      assert.equal((await deploy.finish({ cliExited: true, exitCode: 1 })).clean, true);
    }
    assert.equal(uploads.report().closureReady, true);
    assert.equal(budget.snapshot().upload, 6);
  } finally {
    uploads.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("before-inventory refuses any function already in the breadth codebase", async () => {
  const { assembleBreadth } = await import("./breadth-assemble.mjs");
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "breadth-preflight-"));
  let occupied = true;
  const assembled = assembleBreadth({
    control: async (_method, url) => {
      if (url.includes("/functions?")) assert.ok(url.includes("/locations/-/"));
      return {
        value: {
          functions: occupied
            ? [
                {
                  name: "unrelated",
                  labels: { "firebase-functions-codebase": "rtdb-breadth-oracle" },
                },
              ]
            : [],
        },
      };
    },
    auth: {},
    sdk: {},
    packet: {},
    budget: createBreadthBudget(),
    runDir: dir,
    projectNumber: "123456789012",
    clock: { now: () => 0, sleep: async () => {} },
    nonce: "nonce",
  });
  try {
    await assert.rejects(assembled.deps.inventory.take(), /codebase already has a function/);
    occupied = false;
    assert.equal((await assembled.deps.inventory.take()).complete, true);
  } finally {
    assembled.uploads.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("function records survive shared validation failures and precede cleanup deletes", async () => {
  const { assembleBreadth } = await import("./breadth-assemble.mjs");
  const { TARGETS } = await import("./breadth-targets.mjs");
  const { mkdtemp, readFile, rm, stat } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "breadth-early-record-"));
  const [gen2, gen1] = TARGETS;
  const records = Object.fromEntries(
    TARGETS.map((target) => [
      target.key,
      {
        name: `projects/${target.project}/locations/${target.region}/functions/${target.functionName}`,
        eventTrigger: { trigger: "unreviewed" },
      },
    ]),
  );
  let deleted = false;
  const assembled = assembleBreadth({
    control: async (method, url) => {
      if (method === "DELETE") {
        const saved = JSON.parse(await readFile(join(dir, "records.json")));
        assert.deepEqual(saved[gen1.key], records[gen1.key]);
        assert.equal((await stat(join(dir, "records.json"))).mode & 0o777, 0o600);
        deleted = true;
        return {
          status: 200,
          value: {
            name: "operations/delete",
            done: true,
            metadata: { target: records[gen1.key].name },
          },
        };
      }
      for (const target of [gen2, gen1])
        if (
          url ===
          `https://cloudfunctions.googleapis.com/${target === gen1 ? "v1" : "v2"}/${records[target.key].name}`
        )
          return deleted && target === gen1
            ? { status: 404, value: {} }
            : { status: 200, value: records[target.key] };
      return { status: 404, value: {} };
    },
    auth: {},
    sdk: {},
    packet: {},
    budget: createBreadthBudget(),
    runDir: dir,
    projectNumber: "123456789012",
    clock: { now: () => 0, sleep: async () => {} },
    nonce: "nonce",
    log: async () => {},
  });
  try {
    await assert.rejects(assembled.deps.ops.gcfv2.read(gen2, {}));
    assert.deepEqual(
      JSON.parse(await readFile(join(dir, "records.json")))[gen2.key],
      records[gen2.key],
    );
    const state = { started: true };
    await assembled.deps.ops.gcfv1.cleanup(gen1, state);
    assert.equal(deleted, true);
    assert.equal(state.cleaned, true, state.cleanupError);
    assert.deepEqual(assembled.deps.records[gen1.key], records[gen1.key]);
  } finally {
    assembled.uploads.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("breadth operations pass registered targets to shared absence checks", async () => {
  const { assembleBreadth } = await import("./breadth-assemble.mjs");
  const { TARGETS } = await import("./breadth-targets.mjs");
  const { mkdtemp, rm } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "breadth-resolved-"));
  const calls = [];
  const assembled = assembleBreadth({
    control: async (method, url) => {
      calls.push([method, url]);
      return url.includes("/functions?")
        ? { status: 200, value: { functions: [] } }
        : { status: 404, value: {} };
    },
    auth: {},
    sdk: {},
    packet: {},
    budget: createBreadthBudget(),
    runDir: dir,
    projectNumber: "123456789012",
    clock: { now: () => 0, sleep: async () => {} },
    nonce: "nonce",
    log: async () => {},
  });
  try {
    for (const target of TARGETS) await assembled.deps.ops[target.generation].assertAbsent(target);
    assert.ok(calls.length >= 3);
    assert.ok(calls.every(([method]) => method === "GET"));
    for (const target of TARGETS.filter((spec) => spec.generation === "gcfv2"))
      assert.equal(assembled.deps.ownedNames({ name: target.functionName }, target), null);
  } finally {
    assembled.uploads.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test("cleanup category admits the reviewed 89-request worst case inside the total ceiling", () => {
  const budget = createBreadthBudget();
  budget.startCleanup();
  for (let i = 0; i < 89; i++) budget.take("cleanup");
  assert.equal(budget.snapshot().cleanup, 89);
  assert.equal(budget.snapshot().total, 89);
  assert.throws(() => budget.take("cleanup"), /cleanup/);
  assert.equal(budget.snapshot().total, 89);
});
