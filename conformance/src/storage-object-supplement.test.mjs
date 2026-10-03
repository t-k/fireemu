import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

let api = {};
try {
  api = await import("./storage-object/supplement.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
}
let runtime = {};
try {
  runtime = await import("./storage-object/supplement-record.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
}

test("supplement declares exact subjects, physical bounds, and retained original conditions", () => {
  assert.equal(typeof api.supplementPlan, "function", "bounded supplement plan is required");
  const plan = api.supplementPlan();
  assert.deepEqual(plan.limits, {
    m1Normal: 25,
    m1Recovery: 6,
    m1: 31,
    m4: 28,
    storage: 59,
    oauth: 1,
    tokeninfo: 1,
    rules: 4,
    bucket: 1,
    record: 66,
    precheck: 8,
    campaign: 140,
  });
  assert.deepEqual(plan.m1, {
    progress: 262144,
    wrongOffset: 262145,
    total: 262147,
    expectedStatus: "UNKNOWN",
  });
  assert.deepEqual(plan.m4.cases, [
    "gcs-omitted",
    "gcs-empty",
    "firebase-omitted",
    "firebase-empty",
  ]);
  assert.equal(plan.retainedOriginalConditionCount, 28);
  assert.equal(plan.parentClosed, false);
  assert.equal(api.supplementPayload().length, 262147);
  assert.deepEqual([...api.supplementPayload().subarray(262144)], [0, 1, 255]);
});

test("M4 requires every whole-bucket and prefix read and records observed 4xx without guessing status", () => {
  assert.equal(typeof api.judgeM4Case, "function");
  const empty = { status: 200, complete: true, body: Buffer.from('{"items":[]}') };
  const subject = { status: 418, complete: true, body: Buffer.from('{"error":"observed"}') };
  const good = { before: [empty, empty, empty], subject, after: [empty, empty, empty] };
  assert.equal(api.judgeM4Case(good), "RECORDED_UNREVIEWED");
  for (const status of [200, 201, 302, 500, null])
    assert.equal(api.judgeM4Case({ ...good, subject: { ...subject, status } }), "UNKNOWN");
  for (let index = 0; index < 6; index++) {
    const changed = structuredClone(good);
    (index < 3 ? changed.before : changed.after)[index % 3] = {
      ...empty,
      body: Buffer.from('{"nextPageToken":"x"}'),
    };
    assert.equal(api.judgeM4Case(changed), "UNKNOWN");
  }
  assert.equal(api.judgeM4Case({ ...good, after: good.after.slice(1) }), "UNKNOWN");
  assert.equal(api.judgeM4Case({ ...good, subject: { ...subject, complete: false } }), "UNKNOWN");
});

test("cleanup requires four consistent positive reads and fresh bytes plus born generation", () => {
  assert.equal(typeof api.cleanupGeneration, "function");
  const payload = api.supplementPayload();
  const generation = "1730000000000000";
  const metadata = {
    status: 200,
    complete: true,
    body: Buffer.from(
      JSON.stringify({ name: "owned/object", bucket: "test.bucket", generation, size: "262147" }),
    ),
  };
  const media = {
    status: 200,
    complete: true,
    body: payload,
    headers: { "x-goog-generation": generation },
  };
  const input = {
    name: "owned/object",
    bucket: "test.bucket",
    bornGeneration: generation,
    reads: [metadata, media, metadata, media],
    fresh: [metadata, media],
  };
  assert.equal(api.cleanupGeneration(input), generation);
  for (let index = 0; index < 6; index++) {
    const changed = { ...input, reads: [...input.reads], fresh: [...input.fresh] };
    (index < 4 ? changed.reads : changed.fresh)[index % (index < 4 ? 4 : 2)] = {
      status: 404,
      complete: true,
      body: Buffer.from("{}"),
    };
    assert.equal(api.cleanupGeneration(changed), null);
  }
  assert.equal(api.cleanupGeneration({ ...input, bornGeneration: "1730000000000001" }), null);
  assert.equal(
    api.cleanupGeneration({
      ...input,
      fresh: [metadata, { ...media, body: Buffer.from("different") }],
    }),
    null,
  );
});

test("finite admission model is sticky and enforces cost, spacing, expiry and family caps", () => {
  assert.equal(typeof api.admissionProblem, "function");
  const base = {
    stage: "record1",
    attempted: 0,
    families: { storage: 0, oauth: 0, tokeninfo: 0, rules: 0, bucket: 0 },
    pending: 0,
    failed: false,
    armed: true,
    sourceCurrent: true,
    grantCurrent: true,
    locksHeld: true,
    now: 2000000,
    started: 2000000,
    previousTerminal: 100000,
    grantExpires: 4000000,
    tokenExpires: 4000000,
    baselineObserved: 2000000,
    costKnown: true,
    priorSpent: 1,
    priorReserved: 2,
    reservation: 3,
    ceiling: 10000000,
  };
  assert.equal(api.admissionProblem(base, "storage"), null);
  const cases = [
    { failed: true },
    { armed: false },
    { sourceCurrent: false },
    { grantCurrent: false },
    { locksHeld: false },
    { pending: 1 },
    { costKnown: false },
    { priorReserved: 10000000 },
    { previousTerminal: 2000000 },
    { now: 3000001 },
    { grantExpires: 2000000 },
    { tokenExpires: 2000000 },
    { baselineObserved: 1600000 },
    { attempted: 66 },
  ];
  for (const delta of cases)
    assert.equal(typeof api.admissionProblem({ ...base, ...delta }, "storage"), "string");
  let state = 0x790;
  for (let sample = 0; sample < 4096; sample++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const family = ["storage", "oauth", "tokeninfo", "rules", "bucket"][state % 5];
    const cap = { storage: 59, oauth: 1, tokeninfo: 1, rules: 4, bucket: 1 }[family];
    const count = (state >>> 8) % (cap + 3);
    const candidate = { ...base, families: { ...base.families, [family]: count } };
    assert.equal(api.admissionProblem(candidate, family) === null, count < cap);
  }
});

test("actual local wire has durable intent before independent peer observation, bounded body and no redirect retry", async () => {
  assert.equal(typeof runtime.observeLocalSupplement, "function");
  const port = Number(process.env.PORT);
  assert.ok(Number.isInteger(port) && port > 0, "run physical observer with portctl");
  const directory = await mkdtemp(join(await realpath(tmpdir()), "object-supplement-wire-"));
  let received = 0;
  const server = createServer(async (_request, response) => {
    received++;
    const lines = (await readFile(join(directory, "events.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.equal(lines.at(-1).kind, "ATTEMPT");
    assert.equal(lines.at(-1).sequence, received);
    response.writeHead(302, { location: "/second" });
    response.end("observed redirect");
  });
  try {
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    const result = await runtime.observeLocalSupplement({
      origin: `http://127.0.0.1:${port}`,
      directory,
      requests: [{ method: "GET", path: "/first", body: "" }],
    });
    assert.equal(received, 1);
    assert.equal(result.exchanges[0].status, 302);
    assert.equal(result.outcome, "UNKNOWN");
    assert.equal(result.sendAuthorized, false);
    const ledger = (await readFile(join(directory, "events.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      ledger.map((row) => row.kind),
      ["STARTED", "ATTEMPT", "RESPONSE", "UNKNOWN"],
    );
    await assert.rejects(
      runtime.observeLocalSupplement({
        origin: "https://storage.googleapis.com",
        directory,
        requests: [],
      }),
      /LOCAL_ONLY/,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
