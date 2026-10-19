import assert from "node:assert/strict";
import { test } from "node:test";

import {
  NUMBER_CONDITIONS,
  NUMBER_DOC,
  NUMBER_EXPRESSIONS,
  PROGRAMS,
  PROBE_DOC,
  SELECT_EXPRESSIONS,
  STATIC_REFUSALS,
  WHERE_CONDITIONS,
} from "./fs-ent-pipeline/corpus.mjs";
import {
  DATABASE,
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-query-index/harness.mjs";
import { LANES, selectLane } from "./fs-query-index/lanes.mjs";

const lane = LANES["fs-ent-pipeline"];

const production = (database = lane.database) =>
  createContext({
    run: "1",
    startedMs: Date.parse("2026-10-20T00:00:00Z"),
    database,
    target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
  });

test("the pipeline lane records into the named Enterprise database without an index file", () => {
  assert.equal(selectLane("fs-ent-pipeline"), lane);
  assert.equal(lane.database, "entpipe1");
  assert.equal(lane.edition, "ENTERPRISE");
  assert.equal(lane.indexes, null);
  assert.equal(lane.taskId, "FS-ENT-ORACLE");
  // The other lanes keep (default).
  assert.equal(LANES["fs-query-index"].database, undefined);
  assert.equal(LANES["fs-data-write-list"].database, undefined);
});

test("contexts name their database and refuse any other", () => {
  assert.equal(databaseName(production()), `projects/${SANDBOX_PROJECT}/databases/entpipe1`);
  assert.equal(
    databaseName(production(DATABASE)),
    `projects/${SANDBOX_PROJECT}/databases/(default)`,
  );
  assert.equal(
    databaseName(
      createContext({
        run: "1",
        target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
      }),
    ),
    `projects/${SANDBOX_PROJECT}/databases/(default)`,
  );
  for (const database of ["entpipe2", "", "(default)/x"]) {
    assert.throws(() => production(database), /not a sandbox database/, database);
  }
});

test("the corpus validates, stays within its budget and only reads pipelines or writes its own collection", () => {
  const requests = validateCorpus(PROGRAMS, "fs-ent-pipeline");
  assert.equal(requests, 199);
  const rpcs = new Set(PROGRAMS.flatMap((p) => p.steps.map((s) => s.rpc)));
  assert.deepEqual([...rpcs].toSorted(), ["commit", "executePipeline"]);
  // The only writes are the order program's single-document commits into `ord`.
  for (const program of PROGRAMS) {
    for (const step of program.steps.filter((s) => s.rpc === "commit")) {
      assert.equal(program.id, "fs-ent-pipeline/results/order");
      assert.equal(step.body.writes.length, 1);
      assert.match(step.body.writes[0].update.name, /^\{docs\}\/ord\/[a-z]+$/);
    }
  }
  const labels = (pairs) => pairs.map(([label]) => label);
  for (const pairs of [
    SELECT_EXPRESSIONS,
    WHERE_CONDITIONS,
    STATIC_REFUSALS,
    NUMBER_EXPRESSIONS,
    NUMBER_CONDITIONS,
  ]) {
    assert.equal(new Set(labels(pairs)).size, pairs.length);
    for (const label of labels(pairs)) assert.match(label, /^[a-z0-9-]+$/);
  }
  // The probe document never holds a run-window time and never sets `x`.
  assert.equal(PROBE_DOC.x, undefined);
  assert.equal(PROBE_DOC.ts.timestampValue.startsWith("2020-"), true);
});

test("O-2 records typed numbers and the select width alone, leaving the O-1 programs as they were", async () => {
  const { programDigest, selectPrograms } = await import("./fs-query-index/run.mjs");
  const o2 = selectPrograms(PROGRAMS, "fs-ent-pipeline/o2/");
  assert.deepEqual(
    o2.map((p) => p.id),
    ["fs-ent-pipeline/o2/numbers", "fs-ent-pipeline/o2/select-width"],
  );
  assert.equal(
    o2.reduce((n, p) => n + p.steps.length, 0),
    37,
  );
  // The O-1 programs keep the digests their production rows were recorded under.
  const recorded = JSON.parse(
    await (await import("node:fs/promises")).readFile(
      new URL("../fs-ent-pipeline-production.json", import.meta.url),
      "utf8",
    ),
  );
  const o1 = PROGRAMS.filter((p) => !p.id.startsWith("fs-ent-pipeline/o2/"));
  assert.equal(o1.length, 6);
  for (const program of o1) {
    assert.equal(recorded.programs[program.id].corpusDigest, programDigest(program), program.id);
  }
  // Doubles are written as doubles, whatever their value.
  assert.deepEqual(NUMBER_DOC.one, { doubleValue: 1 });
  assert.deepEqual(NUMBER_DOC.dz, { doubleValue: 0 });
  assert.deepEqual(NUMBER_DOC.nz, { doubleValue: "-0" });
  assert.deepEqual(NUMBER_DOC.d63, { doubleValue: 2 ** 63 });
  assert.equal(JSON.parse(JSON.stringify(NUMBER_DOC.d63)).doubleValue, 9223372036854775808);
  assert.deepEqual(NUMBER_DOC.i53p, { integerValue: "9007199254740993" });
  assert.deepEqual(NUMBER_DOC.inf, { doubleValue: "Infinity" });
  // The width steps select exactly 64 and 65 distinct aliases, over REST and gRPC.
  const width = o2[1];
  assert.deepEqual(
    width.steps.map((step) => [step.id, step.transport ?? "rest"]),
    [
      ["select-64", "rest"],
      ["select-64-grpc", "grpc"],
      ["select-65", "rest"],
      ["select-65-grpc", "grpc"],
    ],
  );
  for (const step of width.steps) {
    const stages = step.body.structuredPipeline.pipeline.stages;
    const aliases = Object.keys(stages[1].args[0].mapValue.fields);
    assert.equal(aliases.length, step.id.startsWith("select-64") ? 64 : 65, step.id);
    assert.equal(new Set(aliases).size, aliases.length);
  }
});

test("every step stays in the named database on both transports", () => {
  for (const ctx of [production()]) {
    for (const program of PROGRAMS) {
      for (const step of program.steps) {
        if ((step.transport ?? "rest") === "grpc") {
          const built = buildGrpcRequest(step, ctx, new Map());
          guardGrpcRequest(built, ctx);
          assert.equal(built.request.database, databaseName(ctx), step.id);
        } else {
          const built = buildRestRequest(step, ctx, new Map());
          guardRestRequest(built, ctx);
          assert.ok(
            built.url.startsWith(
              `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/entpipe1/documents`,
            ),
            built.url,
          );
        }
      }
    }
  }
});

test("a request built for the named database is refused in (default) and the reverse", () => {
  const step = PROGRAMS[0].steps[0];
  const named = buildRestRequest(step, production(), new Map());
  assert.throws(
    () => guardRestRequest(named, production(DATABASE)),
    /outside the sandbox database/,
  );
  const fallback = buildRestRequest(step, production(DATABASE), new Map());
  assert.throws(() => guardRestRequest(fallback, production()), /outside the sandbox database/);
  const grpcStep = PROGRAMS.find((p) => p.id.endsWith("metadata")).steps.find(
    (s) => s.transport === "grpc",
  );
  const grpcNamed = buildGrpcRequest(grpcStep, production(), new Map());
  assert.throws(() => guardGrpcRequest(grpcNamed, production(DATABASE)), /outside the sandbox/);
});

// --- run.mjs: recording context, preflight and fixture for the pipeline lane ---

const run = await import("./fs-query-index/run.mjs");
const { mkdtemp, readFile: readText, rm: remove } = await import("node:fs/promises");
const { tmpdir } = await import("node:os");
const { join: joinPath } = await import("node:path");

test("a production recording addresses its lane's database, wipes and seeds included", () => {
  for (const [id, expected] of [
    ["fs-ent-pipeline", "entpipe1"],
    ["fs-query-index", "(default)"],
    ["fs-data-write-list", "(default)"],
  ]) {
    const ctx = run.productionContext({ lane: LANES[id], run: "1", token: "t" });
    assert.equal(databaseName(ctx), `projects/${SANDBOX_PROJECT}/databases/${expected}`, id);
    assert.equal(ctx.target.quotaProject, SANDBOX_PROJECT);
  }
  // Renormalizing a saved recording keeps its start and its lane's database.
  const ctx = run.productionContext({
    lane: lane,
    run: "7",
    startedMs: 123,
    token: "renormalize",
  });
  assert.equal(ctx.startedMs, 123);
  assert.equal(ctx.database, "entpipe1");
});

const enterprise = {
  databaseEdition: "ENTERPRISE",
  firestoreDataAccessMode: "DATA_ACCESS_MODE_ENABLED",
  type: "FIRESTORE_NATIVE",
};

test("the named-database preflight checks edition, data access, type and emptiness", async () => {
  const calls = [];
  const get = async (path) => {
    calls.push(path);
    return { ...enterprise };
  };
  const empty = async (_token, database) => {
    calls.push(`documents:${database}`);
    return [];
  };
  await run.preflightNamedDatabase("t", { lane, get, documents: empty });
  assert.deepEqual(calls, [`projects/${SANDBOX_PROJECT}/databases/entpipe1`, "documents:entpipe1"]);
  for (const [key, bad] of [
    ["databaseEdition", "STANDARD"],
    ["firestoreDataAccessMode", "DATA_ACCESS_MODE_DISABLED"],
    ["firestoreDataAccessMode", undefined],
    ["type", "DATASTORE_MODE"],
  ]) {
    await assert.rejects(
      run.preflightNamedDatabase("t", {
        lane,
        get: async () => ({ ...enterprise, [key]: bad }),
        documents: empty,
      }),
      new RegExp(key),
    );
  }
  await assert.rejects(
    run.preflightNamedDatabase("t", {
      lane,
      get: async () => ({ ...enterprise }),
      documents: async () => [`projects/${SANDBOX_PROJECT}/databases/entpipe1/documents/c/d`],
    }),
    /not empty/,
  );
});

test("the emptiness read queries the named database and gives up on a hung read", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, init });
    return { ok: true, json: async () => [{ readTime: "x" }] };
  };
  assert.deepEqual(await run.databaseDocuments("t", "entpipe1", fetchImpl), []);
  assert.equal(
    seen[0].url,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/entpipe1/documents:runQuery`,
  );
  assert.ok(seen[0].init.signal instanceof AbortSignal);
  assert.equal(seen[0].init.headers["x-goog-user-project"], SANDBOX_PROJECT);
});

test("the pipeline lane's fixture names its target, has no index file and passes the secret scan", async () => {
  const dir = await mkdtemp(joinPath(tmpdir(), "fs-ent-pipeline-fixture-"));
  try {
    const programs = PROGRAMS.slice(0, 2);
    const recording = (marker) => ({
      results: Object.fromEntries(
        programs.map((p) => [
          p.id,
          {
            steps: Object.fromEntries(
              p.steps.map((s) => [s.id, { status: 200, body: [{ marker }] }]),
            ),
          },
        ]),
      ),
    });
    const fixturePath = joinPath(dir, "fixture.json");
    const differing = await run.writeFixture({
      programs,
      recordings: [recording("a"), recording("a")],
      meta: { harness: "h", startedAt: "2026-10-20T00:00:00Z", sha: "s" },
      secrets: ["fireemu-oracle-query", "123456789012"],
      lane,
      fixturePath,
    });
    const fixture = JSON.parse(await readText(fixturePath, "utf8"));
    assert.equal(fixture.recordedAgainst.target, lane.target);
    assert.equal("indexes" in fixture.recordedAgainst, false);
    assert.deepEqual(Object.keys(fixture.programs), programs.map((p) => p.id).toSorted());
    assert.equal(fixture.programs[programs[0].id].second, undefined);
    assert.ok(differing !== undefined);
    // A recording that leaks the project id is refused before anything is written.
    await assert.rejects(
      run.writeFixture({
        programs,
        recordings: [recording(`projects/fireemu-oracle-query`), recording("a")],
        meta: { harness: "h", startedAt: "2026-10-20T00:00:00Z", sha: "s" },
        secrets: ["fireemu-oracle-query"],
        lane,
        fixturePath: joinPath(dir, "leak.json"),
      }),
    );
  } finally {
    await remove(dir, { recursive: true, force: true });
  }
});
