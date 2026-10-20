import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CELLS_PER_STEP,
  O3_ALIASES,
  O3_CELLS,
  O3_CONDITIONS,
  O3_KIND_DOC,
  O3_LITERALS,
  COMPARISON_CELLS,
  KINDS,
  KIND_DOC,
  NON_BOOLEAN_CONDITIONS,
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
  DATABASES,
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-ent-pipeline/harness.mjs";
import * as queryHarness from "./fs-query-index/harness.mjs";
import { LANES, selectLane } from "./fs-query-index/lanes.mjs";

const lane = LANES["fs-ent-pipeline"];

const production = (database = lane.database) =>
  createContext({
    run: "1",
    startedMs: Date.parse("2026-10-20T00:00:00Z"),
    database,
    target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
  });

test("the pipeline lane has its own copy of the request layer and the others keep theirs", async () => {
  const { readFile } = await import("node:fs/promises");
  const read = (path) => readFile(new URL(path, import.meta.url), "utf8");
  assert.equal(lane.harness, "src/fs-ent-pipeline");
  assert.equal(LANES["fs-query-index"].harness, "src/fs-query-index");
  assert.equal(LANES["fs-data-write-list"].harness, "src/fs-query-index");
  // The session copy is byte for byte the shared one: only the harness differs, by the named
  // database. The shared harness has no named database at all.
  assert.equal(
    await read("./fs-ent-pipeline/session.mjs"),
    await read("./fs-query-index/session.mjs"),
  );
  assert.equal(queryHarness.DATABASES, undefined);
  assert.notEqual(DATABASES, undefined);
  // Every recorded row is bound to the digest of the lane's own two files (no index file).
  const { createHash } = await import("node:crypto");
  const own = createHash("sha256")
    .update(
      `${await read("./fs-ent-pipeline/harness.mjs")}\n${await read("./fs-ent-pipeline/session.mjs")}\n`,
    )
    .digest("hex");
  const recorded = JSON.parse(await read("../fs-ent-pipeline-production.json"));
  for (const [id, program] of Object.entries(recorded.programs)) {
    assert.equal(program.harnessDigest, own, id);
  }
});

test("run.mjs digests the pipeline lane's own request layer: the digest its rows were recorded under", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { readFile } = await import("node:fs/promises");
  const digestOf = async (laneId) => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `const r = await import(${JSON.stringify(new URL("./fs-query-index/run.mjs", import.meta.url).href)}); console.log(await r.harnessDigest());`,
      ],
      { env: { ...process.env, FIREEMU_SANDBOX_LANE: laneId } },
    );
    return stdout.trim();
  };
  const recorded = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  );
  const ent = await digestOf("fs-ent-pipeline");
  for (const [id, program] of Object.entries(recorded.programs)) {
    assert.equal(program.harnessDigest, ent, id);
  }
  // The query lanes digest the shared request layer, which is not the pipeline lane's.
  const query = JSON.parse(
    await readFile(new URL("../fs-query-index-production.json", import.meta.url), "utf8"),
  );
  const queryDigests = new Set(Object.values(query.programs).map((p) => p.harnessDigest));
  const shared = await digestOf("fs-query-index");
  assert.notEqual(shared, ent);
  assert.ok(queryDigests.has(shared), [...queryDigests].join(", "));
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
  assert.equal(requests, 300);
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
    NON_BOOLEAN_CONDITIONS,
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
    [
      "fs-ent-pipeline/o2/numbers",
      "fs-ent-pipeline/o2/select-width",
      "fs-ent-pipeline/o2/comparisons",
    ],
  );
  assert.equal(
    o2.reduce((n, p) => n + p.steps.length, 0),
    58,
  );
  // The O-1 programs keep the digests their production rows were recorded under.
  const recorded = JSON.parse(
    await (
      await import("node:fs/promises")
    ).readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  );
  const o1 = PROGRAMS.filter((p) => !/^fs-ent-pipeline\/o[23]\//.test(p.id));
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

test("O-2 compares every pair of kinds and each kind with itself under every comparison, in steps below the select width", () => {
  const program = PROGRAMS.find((p) => p.id === "fs-ent-pipeline/o2/comparisons");
  const cells = new Map(
    COMPARISON_CELLS.map(([alias, left, right, op]) => [alias, { left, right, op }]),
  );
  assert.equal(cells.size, COMPARISON_CELLS.length);
  const ops = [
    "equal",
    "not_equal",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
  ];
  for (const op of ops) {
    for (const left of KINDS) {
      for (const right of KINDS) {
        if (left !== right)
          assert.ok(cells.has(`${op}__${left}__${right}`), `${op} ${left} ${right}`);
      }
    }
    // NaN and null against themselves, two missing fields, a missing field against a value.
    for (const pair of [
      "nan__nan",
      "n__n",
      "x__y",
      "x__i",
      "i__x",
      "ts__ts2",
      "ts2__ts",
      "g__g2",
      "m__m2",
      "r__r2",
      "by__by2",
      "arr__arr2",
    ]) {
      assert.ok(cells.has(`${op}__${pair}`), `${op} ${pair}`);
    }
  }
  assert.equal(cells.size, 6 * (11 * 10 + 20 + 5));
  // Every cell is selected exactly once, in steps of at most CELLS_PER_STEP aliases (the
  // official emulator answers at most 64), each alias a plain identifier.
  const selected = [];
  for (const step of program.steps.filter((s) => s.id.startsWith("cells-"))) {
    const fields = step.body.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields;
    const aliases = Object.keys(fields);
    assert.ok(aliases.length <= CELLS_PER_STEP && CELLS_PER_STEP < 64, step.id);
    for (const alias of aliases) {
      assert.match(alias, /^[a-z][a-z0-9_]*$/);
      const { left, right, op } = cells.get(alias);
      assert.deepEqual(fields[alias], {
        functionValue: {
          name: op,
          args: [{ fieldReferenceValue: left }, { fieldReferenceValue: right }],
        },
      });
    }
    selected.push(...aliases);
  }
  assert.deepEqual(selected.toSorted(), [...cells.keys()].toSorted());
  // The probe document holds two values of every kind but never `x` or `y`.
  for (const kind of KINDS) assert.ok(KIND_DOC[kind], kind);
  assert.equal(KIND_DOC.x, undefined);
  assert.equal(KIND_DOC.y, undefined);
  assert.deepEqual(
    program.steps.filter((s) => s.id.startsWith("where-")).map((s) => s.id),
    ["where-document-id", "where-parent", "where-array", "where-map"],
  );
});

test("the O-2 launch stays within its request cap: the worst case is 2 x (58 + 50) + 5", async () => {
  const { ceilings, selectPrograms } = await import("./fs-query-index/run.mjs");
  const o2 = selectPrograms(PROGRAMS, "fs-ent-pipeline/o2/");
  // The harness ceiling is a base of 20 plus 8 and the seed batches per program.
  assert.deepEqual(ceilings(o2), { maxRequests: 58, maxHarnessRequests: 50 });
  // S0 one describe, the preflight two reads, two recordings, A1 two read-backs (E line: 230).
  const worst = 1 + 2 + 2 * (58 + 50) + 2;
  assert.equal(worst, 221);
  assert.ok(worst <= 230);
});

test("a wipe read that is not JSON fails its program and the cleanup wipe still runs", async () => {
  const { runCorpus } = await import("./fs-ent-pipeline/session.mjs");
  const ctx = production();
  const program = {
    id: "fs-ent-pipeline/o2/wipe-probe",
    seed: [["t/d", { i: { integerValue: "1" } }]],
    steps: [
      {
        id: "s",
        rpc: "executePipeline",
        body: {
          structuredPipeline: {
            pipeline: { stages: [{ name: "collection", args: [{ referenceValue: "/t" }] }] },
          },
        },
      },
    ],
  };
  // The first wipe reads an empty database, the program's cleanup wipe reads a body that is
  // not JSON, and the run's final wipe reads an empty database again.
  const wipeReads = ["[]", "<html>not json</html>", "[]"];
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const path = String(url);
    calls.push(path);
    const text = path.endsWith(":runQuery")
      ? wipeReads.shift()
      : path.endsWith(":commit")
        ? "{}"
        : `[{"executionTime": "2026-10-20T00:00:00Z"}]`;
    return new Response(text, { status: 200 });
  };
  let out;
  try {
    out = await runCorpus([program], ctx, { maxRequests: 1, maxHarnessRequests: 20 });
  } finally {
    globalThis.fetch = original;
  }
  // The program is a harness failure, not a row, so record-production ends as
  // recorded-with-program-failures rather than aborting.
  assert.deepEqual(Object.keys(out.results), []);
  assert.equal(out.failures.length, 1);
  assert.equal(out.failures[0].program, program.id);
  // Three wipe reads: before the program, its cleanup after the failure, and the final one.
  assert.equal(calls.filter((path) => path.endsWith(":runQuery")).length, 3);
  assert.equal(wipeReads.length, 0);
});

test("O-3 records only its four new programs, within its request cap: 2 x (80 + 60) + 5", async () => {
  const { ceilings, programDigest, selectPrograms } = await import("./fs-query-index/run.mjs");
  const { readFile } = await import("node:fs/promises");
  const o3 = selectPrograms(PROGRAMS, "fs-ent-pipeline/o3/");
  assert.deepEqual(
    o3.map((p) => p.id),
    [
      "fs-ent-pipeline/o3/aliases",
      "fs-ent-pipeline/o3/comparisons",
      "fs-ent-pipeline/o3/literals",
      "fs-ent-pipeline/o3/functions",
    ],
  );
  // The harness ceiling is a base of 20 plus 8 and the seed batches per program.
  assert.deepEqual(ceilings(o3), { maxRequests: 80, maxHarnessRequests: 60 });
  // S0 one describe, the preflight two reads, two recordings, A1 two read-backs.
  const worst = 1 + 2 + 2 * (80 + 60) + 2;
  assert.equal(worst, 285);
  // The O-1 and O-2 programs are recorded already and keep their digests.
  const recorded = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  ).programs;
  for (const program of PROGRAMS.filter((p) => !p.id.startsWith("fs-ent-pipeline/o3/"))) {
    assert.equal(recorded[program.id]?.corpusDigest, programDigest(program), program.id);
  }
  for (const program of o3) assert.equal(recorded[program.id], undefined, program.id);
  // Each O-3 cell step selects at most CELLS_PER_STEP aliases, each cell once.
  const comparisons = o3[1].steps.filter((s) => s.id.startsWith("cells-"));
  const aliases = comparisons.flatMap((s) =>
    Object.keys(s.body.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields),
  );
  assert.ok(
    comparisons.every(
      (s) =>
        Object.keys(s.body.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields).length <=
        CELLS_PER_STEP,
    ),
  );
  assert.deepEqual(aliases.toSorted(), O3_CELLS.map(([alias]) => alias).toSorted());
  assert.equal(O3_CELLS.length, 6 * (3 + 2 * 12 + 2 * 9));
  // The alias lengths sit on both sides of the official emulator's 1500-byte boundary, which
  // counts the unquoted segments joined with '.'; the raw length tells the rows apart.
  const joined = (alias) =>
    Buffer.byteLength(alias.replace(/\\(.)|`/g, (_, escaped) => escaped ?? ""));
  const lengths = Object.fromEntries(
    O3_ALIASES.filter(([label]) => /-\d{4}$/.test(label)).map(([label, alias]) => [
      label,
      [joined(alias), Buffer.byteLength(alias)],
    ]),
  );
  assert.deepEqual(lengths, {
    "plain-1499": [1499, 1499],
    "plain-1500": [1500, 1500],
    "plain-1501": [1501, 1501],
    "quoted-inner-1497": [1497, 1499],
    "quoted-inner-1498": [1498, 1500],
    "quoted-inner-1499": [1499, 1501],
    "quoted-inner-1500": [1500, 1502],
    "dotted-1499": [1499, 1499],
    "dotted-1500": [1500, 1500],
    "quoted-dotted-1499": [1499, 1501],
    "quoted-dotted-1500": [1500, 1502],
    "escaped-1499": [1499, 1502],
    "escaped-1500": [1500, 1503],
    "invalid-1500": [1500, 1500],
  });
  // The empty alias is asked over both transports.
  assert.deepEqual(
    o3[0].steps.filter((s) => s.id.startsWith("empty")).map((s) => [s.id, s.transport ?? "rest"]),
    [
      ["empty-segment", "rest"],
      ["empty-quoted", "rest"],
      ["empty", "rest"],
      ["empty-grpc", "grpc"],
    ],
  );
  // A vector is written as a vector.
  assert.equal(O3_KIND_DOC.v.mapValue.fields.__type__.stringValue, "__vector__");
  // Every field a cell or a where condition reads is seeded, except the missing field x.
  const seeded = Object.keys(o3[1].seed[0][1]);
  const read = [
    ...O3_CELLS.flatMap(([, left, right]) => [left, right]),
    ...O3_CONDITIONS.flatMap(([, c]) => (c.fieldReferenceValue ? [c.fieldReferenceValue] : [])),
  ];
  assert.deepEqual(
    [...new Set(read)].filter((f) => !seeded.includes(f)),
    ["x"],
  );
  // -0.0 is asked as a select literal and inside an array literal, written with its sign.
  const literals = Object.fromEntries(O3_LITERALS);
  assert.deepEqual(literals["negative-zero"], { doubleValue: "-0" });
  assert.deepEqual(literals["negative-zero-in-array"].arrayValue.values[1], { doubleValue: "-0" });
});

test("the committed REST request export is the corpus's", async () => {
  const { EXPORT, exportText } = await import("./fs-ent-pipeline/export-requests.mjs");
  const { readFile } = await import("node:fs/promises");
  assert.equal(await readFile(EXPORT, "utf8"), exportText());
  const exported = JSON.parse(exportText());
  // Only the programs the fixture records: O-3 joins after its recording.
  const recordedIds = Object.keys(
    JSON.parse(
      await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
    ).programs,
  );
  const recordedPrograms = PROGRAMS.filter((p) => recordedIds.includes(p.id));
  assert.equal(exported.programs.length, recordedPrograms.length);
  assert.equal(recordedPrograms.length, 9);
  const rest = recordedPrograms
    .flatMap((p) => p.steps)
    .filter((s) => (s.transport ?? "rest") === "rest");
  assert.equal(
    exported.programs.reduce((n, p) => n + p.steps.length, 0),
    rest.length,
  );
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
    // Each lane names its database through its own request layer.
    const name = id === "fs-ent-pipeline" ? databaseName : queryHarness.databaseName;
    assert.equal(name(ctx), `projects/${SANDBOX_PROJECT}/databases/${expected}`, id);
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
