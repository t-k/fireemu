import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  CELLS_PER_STEP,
  O3_ALIASES,
  O4_ALIASES,
  O4_CELLS,
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
  PROGRAMS as ALL_PROGRAMS,
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

// The O-8A programs join the pinned counts below after their recording;
// fs-ent-pipeline-o8a.test.mjs covers them until then.
const PROGRAMS = ALL_PROGRAMS.filter((program) => !program.id.startsWith("fs-ent-pipeline/o8a/"));

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
  assert.equal(requests, 1084);
  const rpcs = new Set(PROGRAMS.flatMap((p) => p.steps.map((s) => s.rpc)));
  assert.deepEqual([...rpcs].toSorted(), ["commit", "executePipeline", "get"]);
  // The only writes are single-document commits into the program's own collection: the order
  // program's into `ord`, and the O-4 geo rows into `geo4`, each read back by a get of that
  // document.
  const own = {
    "fs-ent-pipeline/results/order": /^\{docs\}\/ord\/[a-z]+$/,
    "fs-ent-pipeline/o4/documents": /^\{docs\}\/geo4\/[a-z-]+$/,
  };
  for (const program of PROGRAMS) {
    // The O-6 programs write their own collections too (vector seeds, ordering writes); their
    // commits are checked in fs-ent-pipeline-o6.test.mjs.
    if (program.id.startsWith("fs-ent-pipeline/o6/")) continue;
    for (const step of program.steps.filter((s) => s.rpc === "commit")) {
      assert.ok(own[program.id], program.id);
      assert.equal(step.body.writes.length, 1);
      assert.match(step.body.writes[0].update.name, own[program.id]);
    }
    for (const step of program.steps.filter((s) => s.rpc === "get")) {
      assert.equal(program.id, "fs-ent-pipeline/o4/documents");
      assert.match(step.parent, /^geo4\/[a-z-]+$/);
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
  const o1 = PROGRAMS.filter((p) => !/^fs-ent-pipeline\/o[234567]\//.test(p.id));
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
  // Every program (O-3 and O-4 since their recordings, 2026-10-20) is recorded under its
  // current digest, and O-3 under the request layer that recorded O-1.
  const recorded = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  ).programs;
  for (const program of PROGRAMS.filter((p) => !p.id.startsWith("fs-ent-pipeline/o5/"))) {
    assert.equal(recorded[program.id]?.corpusDigest, programDigest(program), program.id);
  }
  for (const program of o3) {
    assert.equal(
      recorded[program.id].harnessDigest,
      recorded["fs-ent-pipeline/px0/aliases"].harnessDigest,
      program.id,
    );
  }
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

test("O-4 records only its seven new programs, comparisons last, within its request cap: 2 x (84 + 88) + 5", async () => {
  const { ceilings, programDigest, selectPrograms } = await import("./fs-query-index/run.mjs");
  const { readFile } = await import("node:fs/promises");
  const o4 = selectPrograms(PROGRAMS, "fs-ent-pipeline/o4/");
  // The comparisons program (the only vector seed) comes last (O-3 presend Should Fix 2).
  assert.deepEqual(
    o4.map((p) => p.id),
    [
      "fs-ent-pipeline/o4/aliases",
      "fs-ent-pipeline/o4/stages",
      "fs-ent-pipeline/o4/conditions",
      "fs-ent-pipeline/o4/literals",
      "fs-ent-pipeline/o4/functions",
      "fs-ent-pipeline/o4/documents",
      "fs-ent-pipeline/o4/comparisons",
    ],
  );
  const vectorSeeds = o4.filter((p) =>
    (p.seed ?? []).some(([, fields]) => JSON.stringify(fields).includes("__vector__")),
  );
  assert.deepEqual(
    vectorSeeds.map((p) => p.id),
    ["fs-ent-pipeline/o4/comparisons"],
  );
  // The harness ceiling is a base of 20 plus 8 and the seed batches per program.
  assert.deepEqual(ceilings(o4), { maxRequests: 84, maxHarnessRequests: 88 });
  // S0 one describe, the preflight two reads, two recordings, A1 two read-backs.
  const worst = 1 + 2 + 2 * (84 + 88) + 2;
  assert.equal(worst, 349);
  // O-1 to O-4 are recorded and keep their digests.
  const recorded = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  ).programs;
  for (const program of PROGRAMS.filter((p) => !p.id.startsWith("fs-ent-pipeline/o5/"))) {
    assert.equal(recorded[program.id]?.corpusDigest, programDigest(program), program.id);
  }
  // O-4 recorded under the request layer that recorded O-1 (2026-10-20).
  for (const program of o4) {
    assert.equal(
      recorded[program.id].harnessDigest,
      recorded["fs-ent-pipeline/px0/aliases"].harnessDigest,
      program.id,
    );
  }
  // The multibyte rows separate bytes from characters (O-3 presend Should Fix 1).
  const unquoted = (alias) => alias.replace(/`/g, "");
  const lengths = Object.fromEntries(
    O4_ALIASES.filter(([label]) => label.startsWith("multibyte")).map(([label, alias]) => [
      label,
      [Buffer.byteLength(unquoted(alias)), [...unquoted(alias)].length],
    ]),
  );
  assert.deepEqual(lengths, {
    "multibyte-1497": [1497, 499],
    "multibyte-1499": [1499, 501],
    "multibyte-1500": [1500, 500],
    "multibyte-dotted-1499": [1499, 501],
    "multibyte-plain-1500": [1500, 500],
  });
  // Different-length vectors under every comparison, both ways.
  assert.equal(O4_CELLS.length, 6 * 4);
  // The geo rows write and read back their own documents only.
  const documents = o4.find((p) => p.id === "fs-ent-pipeline/o4/documents");
  assert.deepEqual(
    documents.steps.map((s) => [s.rpc, s.parent ?? s.body.writes[0].update.name]),
    [
      ["commit", "{docs}/geo4/empty"],
      ["get", "geo4/empty"],
      ["commit", "{docs}/geo4/longitude-only"],
      ["get", "geo4/longitude-only"],
      ["commit", "{docs}/geo4/zero-latitude"],
      ["get", "geo4/zero-latitude"],
    ],
  );
});

test("the committed REST request export is the corpus's", async () => {
  const { EXPORT, exportText } = await import("./fs-ent-pipeline/export-requests.mjs");
  const { readFile } = await import("node:fs/promises");
  assert.equal(await readFile(EXPORT, "utf8"), exportText());
  const exported = JSON.parse(exportText());
  // Every recorded program contributes its exact exported REST requests.
  const recordedIds = Object.keys(
    JSON.parse(
      await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
    ).programs,
  );
  const recordedPrograms = PROGRAMS.filter((p) => recordedIds.includes(p.id));
  assert.equal(exported.programs.length, recordedPrograms.length);
  assert.equal(recordedPrograms.length, 55);
  assert.deepEqual(recordedIds.toSorted(), PROGRAMS.map((p) => p.id).toSorted());
  assert.deepEqual(exported.programs.map((p) => p.id).toSorted(), recordedIds.toSorted());
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

// --- seeds that production may refuse go through recorded steps ---

test("a vector reaches the harness seed only in the programs recorded before seed commits", async () => {
  const { HARNESS_VECTOR_SEEDS, seedHoldsVector } = await import("./fs-ent-pipeline/corpus.mjs");
  // A refused harness seed is fatal and ends the recording, so a new program writes a vector
  // with a recorded commit step (seedCommit), whose refusal is that step's row.
  assert.deepEqual(
    PROGRAMS.filter(seedHoldsVector).map((p) => p.id),
    HARNESS_VECTOR_SEEDS,
  );
  assert.deepEqual(HARNESS_VECTOR_SEEDS, [
    "fs-ent-pipeline/o3/comparisons",
    "fs-ent-pipeline/o4/comparisons",
  ]);
  const { vec, map: mapValue, arr, int } = await import("./fs-query-index/values.mjs");
  const program = (fields) => ({ id: "fs-ent-pipeline/o5/x", seed: [["x5/d", fields]], steps: [] });
  for (const fields of [
    { v: vec(1) },
    { m: mapValue({ deep: mapValue({ v: vec(1, 2) }) }) },
    { a: arr(int(1), vec(3)) },
  ]) {
    assert.equal(seedHoldsVector(program(fields)), true, JSON.stringify(fields));
  }
  for (const fields of [
    { i: int(1) },
    // A map with a `__type__` key that is not the vector marker is not a vector.
    { m: mapValue({ __type__: { stringValue: "x" }, value: arr(int(1)) }) },
    { m: mapValue({ type: { stringValue: "__vector__" } }) },
  ]) {
    assert.equal(seedHoldsVector(program(fields)), false, JSON.stringify(fields));
  }
  assert.equal(seedHoldsVector({ id: "p", steps: [] }), false);
});

test("a seed commit is a reviewed single-document write into the named database", async () => {
  const { seedCommit } = await import("./fs-ent-pipeline/corpus.mjs");
  const { vec } = await import("./fs-query-index/values.mjs");
  const fields = { v: vec(1, 2), w: vec(3) };
  const step = seedCommit("seed-d", "cm5/d", fields);
  assert.deepEqual(step, {
    id: "seed-d",
    rpc: "commit",
    body: { writes: [{ update: { name: "{docs}/cm5/d", fields } }] },
  });
  const program = { id: "fs-ent-pipeline/o5/seeded", seed: [], steps: [step] };
  assert.equal(validateCorpus([program], "fs-ent-pipeline"), 1);
  const ctx = production();
  const request = buildRestRequest(step, ctx, new Map());
  assert.equal(
    request.url,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/entpipe1/documents:commit`,
  );
  const sent = JSON.parse(request.init.body);
  assert.equal(
    sent.writes[0].update.name,
    `projects/${SANDBOX_PROJECT}/databases/entpipe1/documents/cm5/d`,
  );
  assert.deepEqual(sent.writes[0].update.fields, fields);
  guardRestRequest(request, ctx);
  assert.throws(() => seedCommit("seed-x", "/abs/d", fields), /relative/);
  assert.throws(() => seedCommit("seed-x", "odd", fields), /document path/);
  // An empty segment, with an even segment count that the length check alone would pass.
  assert.throws(() => seedCommit("seed-x", "a//b/c", fields), /document path/);
  assert.throws(() => seedCommit("seed-x", "a/b/c/", fields), /document path/);
});

test("O-5 original six programs retain their request cap: 2 x (240 + 80) + 5", async () => {
  const { ceilings, programDigest, selectPrograms } = await import("./fs-query-index/run.mjs");
  const { readFile } = await import("node:fs/promises");
  const {
    O5_FUNCTION_NAMES,
    O5_FUNCTION_ORDER,
    O5_LITERAL_KEYS,
    O5_NAMES,
    O5_STAGE_ORDER,
    O5_VALUE_SHAPES,
    seedHoldsVector,
  } = await import("./fs-ent-pipeline/corpus.mjs");
  // This historical subset is fixed; the dedicated coverage suite checks the full selector.
  const originalIds = new Set([
    "fs-ent-pipeline/o5/names",
    "fs-ent-pipeline/o5/literal-keys",
    "fs-ent-pipeline/o5/function-order",
    "fs-ent-pipeline/o5/stage-order",
    "fs-ent-pipeline/o5/value-shapes",
    "fs-ent-pipeline/o5/function-names",
  ]);
  const o5 = selectPrograms(PROGRAMS, "fs-ent-pipeline/o5/").filter((program) =>
    originalIds.has(program.id),
  );
  assert.deepEqual(
    o5.map((p) => p.id),
    [
      "fs-ent-pipeline/o5/names",
      "fs-ent-pipeline/o5/literal-keys",
      "fs-ent-pipeline/o5/function-order",
      "fs-ent-pipeline/o5/stage-order",
      "fs-ent-pipeline/o5/value-shapes",
      "fs-ent-pipeline/o5/function-names",
    ],
  );
  assert.deepEqual(
    o5.map((p) => p.steps.length),
    [
      O5_NAMES.length,
      O5_LITERAL_KEYS.length,
      O5_FUNCTION_ORDER.length,
      O5_STAGE_ORDER.length,
      O5_VALUE_SHAPES.length,
      O5_FUNCTION_NAMES.length,
    ],
  );
  // The PX1d review round 2 shapes strict refuses (stage order, limit and offset; value types,
  // vectors, literal keys and the argument checks of the functions fireemu runs).
  assert.deepEqual(
    [
      O5_NAMES.length,
      O5_LITERAL_KEYS.length,
      O5_FUNCTION_ORDER.length,
      O5_STAGE_ORDER.length,
      O5_VALUE_SHAPES.length,
    ],
    [5, 6, 13, 14, 23],
  );
  // Reads only: every step is a REST executePipeline in the program's own collection, and each
  // program seeds one document without a vector through the harness.
  for (const program of o5) {
    assert.equal(program.seed.length, 1, program.id);
    assert.equal(seedHoldsVector(program), false, program.id);
    const own = program.seed[0][0].split("/")[0];
    for (const s of program.steps) {
      assert.equal(s.rpc, "executePipeline", `${program.id}#${s.id}`);
      assert.equal(s.transport, undefined, `${program.id}#${s.id}`);
      const [first] = s.body.structuredPipeline.pipeline.stages;
      assert.deepEqual(first, { name: "collection", args: [{ referenceValue: `/${own}` }] });
    }
  }
  assert.deepEqual(ceilings(o5), { maxRequests: 240, maxHarnessRequests: 80 });
  const worst = 1 + 2 + 2 * (240 + 80) + 2;
  assert.equal(worst, 645);
  // Bind the populated O5 capture while preserving the historical six-program cap above.
  const recorded = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  ).programs;
  assert.deepEqual(Object.keys(recorded).toSorted(), PROGRAMS.map((p) => p.id).toSorted());
  const allO5 = PROGRAMS.filter((p) => p.id.startsWith("fs-ent-pipeline/o5/"));
  assert.equal(allO5.length, 8);
  assert.equal(
    allO5.reduce((n, p) => n + p.steps.length, 0),
    310,
  );
  const harness = createHash("sha256")
    .update(await readFile(new URL("./fs-ent-pipeline/harness.mjs", import.meta.url), "utf8"))
    .update("\n")
    .update(await readFile(new URL("./fs-ent-pipeline/session.mjs", import.meta.url), "utf8"))
    .update("\n")
    .digest("hex");
  for (const program of allO5) {
    assert.equal(recorded[program.id]?.corpusDigest, programDigest(program), program.id);
    assert.equal(recorded[program.id]?.harnessDigest, harness, program.id);
    assert.deepEqual(
      Object.keys(recorded[program.id].steps).toSorted(),
      program.steps.map((s) => s.id).toSorted(),
      program.id,
    );
  }
  const earlier = Object.fromEntries(
    Object.entries(recorded)
      .filter(([id]) => !/^fs-ent-pipeline\/o[567]\//.test(id))
      .sort(([a], [b]) => a.localeCompare(b)),
  );
  assert.equal(Object.keys(earlier).length, 20);
  assert.equal(
    createHash("sha256").update(JSON.stringify(earlier)).digest("hex"),
    "a9e2320e7eb12cf32fc9085730692640fd9170bdcf8c88a9a1754977ba389307",
  );
  for (const program of PROGRAMS.filter((p) => !p.id.startsWith("fs-ent-pipeline/o5/"))) {
    assert.equal(recorded[program.id]?.corpusDigest, programDigest(program), program.id);
  }
});

test("the O-5 name sweep calls every registry and SDK name once, each under its own step", async () => {
  const { O5_FUNCTION_NAMES, functionNameStep } = await import("./fs-ent-pipeline/corpus.mjs");
  const sweep = PROGRAMS.find((p) => p.id === "fs-ent-pipeline/o5/function-names");
  assert.equal(new Set(O5_FUNCTION_NAMES).size, O5_FUNCTION_NAMES.length);
  assert.equal(O5_FUNCTION_NAMES.length, 179);
  // The registry's operator spellings, the names the official emulator does not know and the
  // names only the SDK sends are all in the sweep; so are the names fireemu runs.
  for (const name of [
    "+",
    "==",
    "AND",
    "<<",
    "switch",
    "score",
    "geo_distance",
    "count",
    "logical_or",
    "between",
    "eq_any",
    "is_nan",
    "is_null",
    "equal",
    "document_id",
    "map",
    "array",
  ]) {
    assert.ok(O5_FUNCTION_NAMES.includes(name), name);
  }
  // Step ids are unique, plain, and map back to their name.
  const ids = O5_FUNCTION_NAMES.map(functionNameStep);
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ids) assert.match(id, /^fn-[a-z0-9_-]+$/);
  assert.equal(functionNameStep(""), "fn-empty");
  assert.equal(functionNameStep("add"), "fn-add");
  assert.equal(functionNameStep("<="), "fn-u3c-3d");
  assert.equal(functionNameStep("AND"), "fn-u41-4e-44");
  assert.deepEqual(
    sweep.steps.map((s) => s.id),
    ids,
  );
  // Each step selects one call of its name: no argument, except the random names (one) and the
  // three array functions the official emulator answers 500 without arguments.
  const field = { fieldReferenceValue: "i" };
  const expected = {
    rand: 1,
    autogen_document_id: 1,
    current_timestamp: 1,
    array_transform: 4,
    array_reverse: 1,
    array_slice: 2,
  };
  for (const [index, s] of sweep.steps.entries()) {
    const [, selectStage] = s.body.structuredPipeline.pipeline.stages;
    const call = selectStage.args[0].mapValue.fields.v.functionValue;
    assert.equal(call.name, O5_FUNCTION_NAMES[index]);
    assert.deepEqual(call.args, Array(expected[call.name] ?? 0).fill(field), call.name);
  }
});

test("the O5 captured INTERNAL response remains an explicit unknown", async () => {
  const { readFile } = await import("node:fs/promises");
  const { isUnknownRow } = await import("./fs-query-index/unknown-rows.mjs");
  const recorded = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  ).programs;
  const rows = Object.entries(recorded)
    .filter(([id]) => id.startsWith("fs-ent-pipeline/o5/"))
    .flatMap(([id, p]) =>
      Object.entries(p.steps)
        .filter(([, value]) => value.status === 500)
        .map(([step, value]) => ({ row: `${id}#${step}`, value })),
    );
  assert.deepEqual(rows, [
    {
      row: "fs-ent-pipeline/o5/appendix#proposed-select-duplicate-quoted-path",
      value: {
        status: 500,
        body: [
          { error: { code: 500, message: "An internal error occurred.", status: "INTERNAL" } },
        ],
      },
    },
  ]);
  assert.equal(isUnknownRow(`${rows[0].row} ${rows[0].value.status}`), true);
});
