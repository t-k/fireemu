// The O-8A pipeline corpus (packet o8a, part A of the FS-PIPELINE follow-up observations): large
// answer framing, the forms of `select` of `__name__`, the stability of the duplicate quoted
// path, error precedence of malformed bodies, expression and literal nesting depth, and base64
// outside executePipeline. Case generation, safety of what the recorder writes, the framing
// summary and the request plan. Nothing here sends a request; the only fetch is an in-memory
// stand-in for the sandbox database.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PROGRAMS, seedHoldsVector } from "./fs-ent-pipeline/corpus.mjs";
import {
  buildGrpcRequest,
  buildRestRequest,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-ent-pipeline/harness.mjs";
import {
  O8A_AREAS,
  O8A_PREFIX,
  O8A_PROGRAMS,
  SUMMARY_ONLY,
  base64Variants,
  documentOfSize,
  largeWrites,
  literalChain,
  functionChain,
} from "./fs-ent-pipeline/o8a-corpus.mjs";
import { O7_PROGRAMS } from "./fs-ent-pipeline/o7-corpus.mjs";
import { o6Plan } from "./fs-ent-pipeline/o6-corpus.mjs";
import { runCorpus } from "./fs-ent-pipeline/session.mjs";
import {
  between,
  fakeFirestore,
  forAll,
  parentOf,
  pick,
  production,
  relative,
  stagesOf,
  steps,
  writtenCollections,
} from "./fs-ent-pipeline/test-support.mjs";
import {
  stripSummaryOnly,
  summarizeFixture,
  summarizeStep,
} from "./fs-ent-pipeline/framing-summary.mjs";
import { ceilings, estimatedUsd, programDigest, selectPrograms } from "./fs-query-index/run.mjs";

const LANE = "fs-ent-pipeline";
const areaSteps = (area) => O8A_AREAS[area].flatMap((program) => program.steps);
const depthOf = (value, key) => {
  let depth = 0;
  let current = value;
  while (current && typeof current === "object") {
    const next = key(current);
    if (next === undefined) break;
    depth += 1;
    current = next;
  }
  return depth;
};

test("O-8A programs follow the O-7 programs in PROGRAMS, under their own prefix, unique and valid", () => {
  assert.ok(O8A_PROGRAMS.length > 0);
  // The O-8A programs follow the O-7 programs, in order (the O-8B to O-8D programs follow them).
  const at = PROGRAMS.findIndex((p) => p.id === O8A_PROGRAMS[0].id);
  assert.deepEqual(PROGRAMS.slice(at, at + O8A_PROGRAMS.length), O8A_PROGRAMS);
  assert.deepEqual(PROGRAMS.slice(at - O7_PROGRAMS.length, at), O7_PROGRAMS);
  assert.equal(new Set(O8A_PROGRAMS.map((p) => p.id)).size, O8A_PROGRAMS.length);
  for (const program of O8A_PROGRAMS) assert.ok(program.id.startsWith(O8A_PREFIX), program.id);
  for (const other of ["fs-ent-pipeline/o6/", "fs-ent-pipeline/o7/"]) {
    assert.ok(!O8A_PREFIX.startsWith(other) && !other.startsWith(O8A_PREFIX));
  }
  validateCorpus(PROGRAMS, LANE);
  assert.deepEqual(
    selectPrograms(PROGRAMS, O8A_PREFIX).map((p) => p.id),
    O8A_PROGRAMS.map((p) => p.id),
  );
  assert.deepEqual(
    Object.values(O8A_AREAS)
      .flat()
      .map((p) => p.id),
    O8A_PROGRAMS.map((p) => p.id),
  );
  // The duplicate-path stability cases can be sent alone, or left out (they may answer 500).
  assert.deepEqual(
    selectPrograms(PROGRAMS, `${O8A_PREFIX}dupquote-`).map((p) => p.id),
    [`${O8A_PREFIX}dupquote-main`],
  );
});

test("O-8A area sizes stay in the assigned ranges", () => {
  const sizes = Object.fromEntries(Object.keys(O8A_AREAS).map((a) => [a, areaSteps(a).length]));
  assert.deepEqual(Object.keys(sizes), [
    "framing",
    "names",
    "dupquote",
    "precedence",
    "nesting",
    "base64",
  ]);
  const reads = (area) => areaSteps(area).filter((s) => s.rpc === "executePipeline").length;
  assert.ok(reads("framing") >= 10 && reads("framing") <= 20, `framing ${reads("framing")}`);
  assert.ok(sizes.names >= 8 && sizes.names <= 16, `names ${sizes.names}`);
  assert.ok(sizes.dupquote >= 6 && sizes.dupquote <= 10, `dupquote ${sizes.dupquote}`);
  assert.ok(sizes.precedence >= 10 && sizes.precedence <= 20, `precedence ${sizes.precedence}`);
  assert.ok(sizes.nesting >= 14 && sizes.nesting <= 24, `nesting ${sizes.nesting}`);
  assert.ok(sizes.base64 >= 18 && sizes.base64 <= 30, `base64 ${sizes.base64}`);
});

/** Every collection id a text names as a reference, in a body or a request. */
const referenced = (text) =>
  [...text.matchAll(/"referenceValue":\s*"\/([a-z0-9]+)/g)].map((m) => m[1]);

test("O-8A steps touch only what their program wrote and use only reviewed methods", () => {
  for (const program of O8A_PROGRAMS) {
    const written = writtenCollections(program);
    assert.ok(written.size > 0, program.id);
    for (const step of program.steps) {
      const where = `${program.id}#${step.id}`;
      assert.ok(["executePipeline", "commit", "get", "runQuery"].includes(step.rpc), where);
      const text = JSON.stringify(step.body ?? {}) + (step.rawBody ?? "");
      for (const name of referenced(text)) assert.ok(written.has(name), `${where} reads ${name}`);
      if (step.rpc === "get") assert.ok(written.has(parentOf(step.parent)), where);
      if (step.rpc === "runQuery") {
        const query = JSON.parse(step.rawBody ?? JSON.stringify(step.body));
        const from = query.structuredQuery.from.map((f) => f.collectionId);
        for (const name of from) assert.ok(written.has(name), `${where} queries ${name}`);
      }
      if (step.rpc === "commit") {
        const body = JSON.parse(step.rawBody ?? JSON.stringify(step.body));
        for (const write of body.writes) {
          const name = relative(write.update?.name ?? write.delete);
          assert.ok(written.has(parentOf(name)), `${where} writes ${name}`);
        }
      }
      if (step.rpc === "executePipeline" && step.body) {
        const list = stagesOf(step);
        assert.equal(list[0].name, "collection", where);
        for (const { name } of list.slice(1)) {
          assert.ok(["select", "where", "limit", "offset"].includes(name), `${where}: ${name}`);
        }
      }
    }
  }
});

test("O-8A seeds and writes stay within the Firestore document and request limits", () => {
  const MAX_DOC = 1_000_000;
  const MAX_REQUEST = 8_000_000;
  const size = (value) => Buffer.byteLength(JSON.stringify(value));
  const nestedArray = (value) =>
    value !== null &&
    typeof value === "object" &&
    ((value.arrayValue?.values ?? []).some((item) => item.arrayValue !== undefined) ||
      Object.values(value).some(nestedArray));
  for (const program of O8A_PROGRAMS) {
    // The harness seeds 500 documents per commit.
    for (let at = 0; at < program.seed.length; at += 500) {
      const batch = program.seed.slice(at, at + 500);
      assert.ok(size(batch) <= MAX_REQUEST, `${program.id} seed batch ${at}: ${size(batch)}`);
    }
    for (const [name, fields] of program.seed) {
      assert.ok(size(fields) <= MAX_DOC, `${program.id} ${name}`);
      assert.ok(!nestedArray(fields) && !seedHoldsVector({ seed: [[name, fields]] }), name);
      assert.equal(name.split("/").length % 2, 0, name);
    }
    for (const step of steps(program, "commit")) {
      const text = step.rawBody ?? JSON.stringify(step.body);
      assert.ok(Buffer.byteLength(text) <= MAX_REQUEST, `${program.id}#${step.id}`);
      const body = JSON.parse(text);
      assert.ok(body.writes.length <= 500);
      for (const write of body.writes) {
        assert.ok(size(write.update?.fields ?? {}) <= MAX_DOC, `${program.id}#${step.id}`);
        assert.ok(!nestedArray(write.update?.fields ?? {}));
      }
    }
  }
});

test("O-8A corpus carries no private or run-window values", () => {
  const text = JSON.stringify(O8A_PROGRAMS).replaceAll(/x{200,}|[a-j]{200,}/g, "~");
  for (const forbidden of [/projects\//, /fireemu-oracle/, /AIza/, /@/, /\b2026-/]) {
    assert.doesNotMatch(text, forbidden);
  }
  for (const [digits] of text.matchAll(/\b\d{9,}\b/g)) assert.fail(`long number ${digits}`);
  for (const match of text.matchAll(/\{[a-z]+\}/g)) assert.equal(match[0], "{docs}");
});

test("O-8A programs are deterministic, JSON stable and named for their transport", async () => {
  const again = (await import(`./fs-ent-pipeline/o8a-corpus.mjs?again=${Date.now()}`)).O8A_PROGRAMS;
  assert.deepEqual(again, O8A_PROGRAMS);
  assert.deepEqual(JSON.parse(JSON.stringify(O8A_PROGRAMS)), O8A_PROGRAMS);
  for (const program of O8A_PROGRAMS) {
    const ids = program.steps.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length, program.id);
    for (const s of program.steps) {
      assert.match(s.id, /^[a-z0-9-]+$/);
      assert.equal(s.id.endsWith("-grpc"), s.transport === "grpc", s.id);
    }
  }
});

test("every O-8A step stays in the named database on both transports", () => {
  const ctx = production();
  for (const program of O8A_PROGRAMS) {
    for (const step of program.steps) {
      if ((step.transport ?? "rest") === "grpc") {
        const built = buildGrpcRequest(step, ctx, new Map());
        guardGrpcRequest(built, ctx);
        assert.equal(built.request.database, databaseName(ctx), step.id);
      } else {
        const built = buildRestRequest(step, ctx, new Map());
        guardRestRequest(built, ctx);
        assert.ok(built.url.includes("/databases/entpipe1/documents"), built.url);
      }
    }
  }
});

// --- generators ---

test("property: a function chain is exactly as deep as asked", () => {
  forAll(
    100,
    (random) => between(random, 1, 120),
    (depth) => {
      const chain = functionChain(depth);
      assert.equal(
        depthOf(chain, (v) => v.functionValue?.args?.[0]),
        depth,
      );
      // Every level is one `array` call with the one argument below it; the leaf is the field.
      let node = chain;
      for (let i = 0; i < depth; i += 1) {
        assert.equal(node.functionValue.name, "array");
        assert.equal(node.functionValue.args.length, 1);
        node = node.functionValue.args[0];
      }
      assert.deepEqual(node, { fieldReferenceValue: "i" });
    },
  );
});

test("property: a literal chain nests the container the asked number of times", () => {
  forAll(
    100,
    (random) => ({ kind: pick(random, ["array", "map"]), depth: between(random, 1, 60) }),
    ({ kind, depth }) => {
      const value = literalChain(kind, depth);
      const inner =
        kind === "array" ? (v) => v.arrayValue?.values?.[0] : (v) => v.mapValue?.fields?.k;
      assert.equal(depthOf(value, inner), depth);
      let node = value;
      for (let i = 0; i < depth; i += 1) node = inner(node);
      assert.deepEqual(node, { integerValue: "1" });
    },
  );
});

test("property: a document of a given size is that long and stays one document", () => {
  forAll(
    60,
    (random) => between(random, 1, 950_000),
    (length) => {
      const fields = documentOfSize(length);
      assert.deepEqual(Object.keys(fields).toSorted(), ["n", "pad"]);
      assert.equal(fields.pad.stringValue.length, length);
      assert.match(fields.pad.stringValue, /^[a-j]+$/);
    },
  );
});

test("property: large writes split any count into commits of at most the asked size, once each", () => {
  forAll(
    100,
    (random) => ({ count: between(random, 1, 60), perCommit: between(random, 1, 12) }),
    ({ count, perCommit }) => {
      const commits = largeWrites("lw", count, 10, perCommit);
      assert.equal(commits.length, Math.ceil(count / perCommit));
      const names = commits.flatMap((c) => c.body.writes.map((w) => w.update.name));
      assert.equal(names.length, count);
      assert.equal(new Set(names).size, count);
      for (const commit of commits) {
        assert.ok(commit.body.writes.length >= 1 && commit.body.writes.length <= perCommit);
        assert.equal(commit.rpc, "commit");
      }
      assert.deepEqual(
        commits.map((c) => c.id),
        commits.map((_, i) => `seed-lw-${i + 1}`),
      );
      // Documents are numbered from 01 across the commits, in order.
      assert.equal(names[0], "{docs}/lw/d01");
      assert.equal(names.at(-1), `{docs}/lw/d${String(count).padStart(2, "0")}`);
    },
  );
});

test("the base64 variants send the bytes as written and name the field as asked", () => {
  const variants = base64Variants();
  const byLabel = Object.fromEntries(variants.map((v) => [v.label, v]));
  assert.equal(byLabel.control.value, "QUJD");
  assert.equal(byLabel.lf.value, "QUJD\nQUJD");
  assert.equal(byLabel.cr.value, "QUJD\rQUJD");
  assert.equal(byLabel.crlf.value, "QUJD\r\nQUJD");
  // A MIME line break after exactly 76 characters.
  assert.equal(byLabel["mime-76"].value.indexOf("\r\n"), 76);
  assert.equal(byLabel["mime-76"].value.length, 76 + 2 + 4);
  assert.equal(byLabel["mixed-plus-underscore"].value, "+_AA");
  assert.equal(byLabel["mixed-minus-slash"].value, "-/AA");
  assert.equal(byLabel["proto-name"].field, "bytes_value");
  for (const v of variants) {
    if (v.label !== "proto-name") assert.equal(v.field, "bytesValue", v.label);
  }
  assert.equal(new Set(variants.map((v) => v.label)).size, variants.length);
  // The commit and read-back steps of the program carry exactly those values.
  const program = O8A_PROGRAMS.find((p) => p.id === `${O8A_PREFIX}base64-main`);
  for (const v of variants) {
    const write = program.steps.find((s) => s.id === `write-${v.label}`);
    const body = JSON.parse(write.rawBody);
    assert.equal(body.writes[0].update.name, `{docs}/bw/${v.label}`);
    assert.deepEqual(body.writes[0].update.fields.b, { [v.field]: v.value });
    const get = program.steps.find((s) => s.id === `get-${v.label}`);
    assert.deepEqual([get.rpc, get.parent], ["get", `bw/${v.label}`]);
    assert.ok(program.steps.indexOf(write) < program.steps.indexOf(get));
  }
});

test("the nesting cases ask for the depths the follow-up needs, on both transports", () => {
  const program = O8A_PROGRAMS.find((p) => p.id === `${O8A_PREFIX}nesting-main`);
  const depthOfStep = (s) => {
    const select = stagesOf(s)[1];
    const value = select.args[0].mapValue.fields.v;
    if (value.functionValue) return ["function", depthOf(value, (v) => v.functionValue?.args?.[0])];
    if (value.arrayValue) return ["array", depthOf(value, (v) => v.arrayValue?.values?.[0])];
    return ["map", depthOf(value, (v) => v.mapValue?.fields?.k)];
  };
  const found = program.steps.map((s) => [s.id, s.transport ?? "rest", ...depthOfStep(s)]);
  for (const depth of [20, 32, 33, 47, 48, 100]) {
    for (const transport of ["rest", "grpc"]) {
      assert.ok(
        found.some((f) => f[1] === transport && f[2] === "function" && f[3] === depth),
        `function ${depth} ${transport}`,
      );
    }
  }
  for (const kind of ["array", "map"]) {
    for (const depth of [20, 21]) {
      assert.ok(
        found.some((f) => f[1] === "rest" && f[2] === kind && f[3] === depth),
        `${kind} ${depth}`,
      );
    }
  }
});

test("the framing programs cross every size the follow-up asks about", () => {
  const small = O8A_PROGRAMS.find((p) => p.id === `${O8A_PREFIX}framing-small`);
  const count = (collection) => small.seed.filter(([n]) => n.startsWith(`${collection}/`)).length;
  assert.deepEqual([count("f5"), count("f50"), count("f500"), count("f5000")], [5, 50, 500, 5000]);
  const large = O8A_PROGRAMS.find((p) => p.id === `${O8A_PREFIX}framing-large`);
  const docs = (collection) =>
    steps(large, "commit")
      .flatMap((s) => JSON.parse(s.rawBody ?? JSON.stringify(s.body)).writes)
      .filter((w) => relative(w.update.name).startsWith(`${collection}/`))
      .map((w) => w.update.fields.pad.stringValue.length);
  const ids = (collection) =>
    small.seed.filter(([n]) => n.startsWith(`${collection}/`)).map(([n]) => n.split("/")[1]);
  assert.deepEqual(ids("f5"), ["d0001", "d0002", "d0003", "d0004", "d0005"]);
  assert.equal(ids("f5000").at(-1), "d5000");
  assert.equal(new Set(ids("f500")).size, 500);
  const largeNames = steps(large, "commit")
    .flatMap((s) => s.body.writes)
    .map((w) => relative(w.update.name));
  assert.equal(new Set(largeNames).size, 45);
  assert.deepEqual(docs("l12"), Array(12).fill(400_000));
  assert.deepEqual(docs("l3"), Array(3).fill(950_000));
  assert.deepEqual(docs("m30"), Array(30).fill(100_000));
  // Every collection is read once over REST and once over gRPC, bare.
  for (const [program, collections] of [
    [small, ["f5", "f50", "f500", "f5000"]],
    [large, ["l12", "l3", "m30"]],
  ]) {
    for (const c of collections) {
      for (const [suffix, transport] of [
        ["rest", "rest"],
        ["grpc", "grpc"],
      ]) {
        const step = program.steps.find((s) => s.id === `${c}-${suffix}`);
        assert.ok(step, `${c}-${suffix}`);
        assert.equal(step.transport ?? "rest", transport);
        assert.equal(stagesOf(step).length, 1, `${c}-${suffix} is bare`);
      }
    }
  }
  assert.deepEqual([...SUMMARY_ONLY].toSorted(), [small.id, large.id].toSorted());
});

// --- the framing summary ---

const unit = (n, extra = {}) => ({
  executionTime: "<t1>",
  results: Array.from({ length: n }, (_, i) => ({ name: `d${i}`, ...extra })),
});

test("a framing summary lists, per response unit, how many results it holds", () => {
  const rest = summarizeStep({ status: 200, body: [unit(3), unit(2), { executionTime: "<t1>" }] });
  assert.equal(rest.transport, "rest");
  assert.equal(rest.status, 200);
  assert.equal(rest.results, 5);
  assert.deepEqual(
    rest.units.map((u) => u.results),
    [3, 2, 0],
  );
  assert.ok(rest.units.every((u) => Number.isInteger(u.jsonBytes) && u.jsonBytes > 0));
  // A body that is one object, not an array, is one unit.
  const single = summarizeStep({ status: 200, body: unit(2) });
  assert.deepEqual(
    single.units.map((u) => u.results),
    [2],
  );
  assert.equal(single.results, 2);
  const grpc = summarizeStep({ transport: "grpc", code: 0, messages: [unit(4), unit(1)] });
  assert.equal(grpc.transport, "grpc");
  assert.equal(grpc.code, 0);
  assert.equal(grpc.results, 5);
  assert.deepEqual(
    grpc.units.map((u) => u.results),
    [4, 1],
  );
  // An error answer has no units, and says what it was.
  const refused = summarizeStep({
    status: 400,
    body: [{ error: { code: 400, status: "INVALID_ARGUMENT", message: "no" } }],
  });
  assert.deepEqual(refused, { transport: "rest", status: 400, results: 0, units: [] });
  assert.deepEqual(summarizeStep({ transport: "grpc", code: 8, details: "x", messages: [] }), {
    transport: "grpc",
    code: 8,
    results: 0,
    units: [],
  });
  // The size of a unit grows with what it holds.
  const small = summarizeStep({ status: 200, body: [unit(1)] }).units[0].jsonBytes;
  const big = summarizeStep({ status: 200, body: [unit(5)] }).units[0].jsonBytes;
  assert.ok(big > small);
});

test("property: a summary keeps every result and every unit, in order", () => {
  forAll(
    100,
    (random) => ({
      sizes: Array.from({ length: between(random, 0, 9) }, () => between(random, 0, 40)),
      transport: pick(random, ["rest", "grpc"]),
    }),
    ({ sizes, transport }) => {
      const units = sizes.map((n) => unit(n));
      const row =
        transport === "rest"
          ? { status: 200, body: units }
          : { transport: "grpc", code: 0, messages: units };
      const summary = summarizeStep(row);
      assert.equal(
        summary.results,
        sizes.reduce((a, b) => a + b, 0),
      );
      assert.deepEqual(
        summary.units.map((u) => u.results),
        sizes,
      );
      assert.equal(summary.transport, transport);
    },
  );
});

test("the summary of a fixture covers the summary-only programs and the strip removes exactly them", () => {
  const ids = [...SUMMARY_ONLY];
  const fixture = {
    version: 1,
    recordedAgainst: { target: "t" },
    programs: {
      "fs-ent-pipeline/o6/sort-ties": {
        corpusDigest: "a",
        steps: { s: { status: 200, body: [] } },
      },
      [ids[0]]: {
        corpusDigest: "b",
        steps: {
          "f5-rest": { status: 200, body: [unit(5)] },
          "f5-grpc": { transport: "grpc", code: 0, messages: [unit(2), unit(3)] },
        },
      },
      [ids[1]]: { corpusDigest: "c", steps: { "l3-rest": { status: 200, body: [unit(3)] } } },
    },
  };
  const summary = summarizeFixture(fixture);
  assert.equal(summary.version, 1);
  assert.deepEqual(Object.keys(summary.programs).toSorted(), ids.toSorted());
  assert.equal(summary.programs[ids[0]].steps["f5-grpc"].units.length, 2);
  // Digests of the programs are kept, so a changed corpus is seen.
  assert.equal(summary.programs[ids[0]].corpusDigest, "b");
  const stripped = stripSummaryOnly(fixture);
  assert.deepEqual(Object.keys(stripped.programs), ["fs-ent-pipeline/o6/sort-ties"]);
  assert.deepEqual(stripped.recordedAgainst, fixture.recordedAgainst);
  // The input is not changed.
  assert.equal(Object.keys(fixture.programs).length, 3);
  assert.throws(() => summarizeFixture({ version: 1, programs: {} }), /summary-only program/);
  // A differing second recording is kept beside the first: a first success followed by a
  // refusal, or other message boundaries, must not disappear with the stripped raw rows.
  const withSecond = structuredClone(fixture);
  withSecond.programs[ids[0]].second = {
    "f5-grpc": { transport: "grpc", code: 8, details: "x", messages: [] },
    "f5-rest": { status: 200, body: [unit(2), unit(3)] },
  };
  const kept = summarizeFixture(withSecond).programs[ids[0]].steps;
  assert.deepEqual(kept["f5-grpc"].second, { transport: "grpc", code: 8, results: 0, units: [] });
  assert.deepEqual(
    kept["f5-rest"].second.units.map((u) => u.results),
    [2, 3],
  );
  assert.deepEqual(
    kept["f5-rest"].units.map((u) => u.results),
    [5],
  );
  // A step whose two recordings agree has no `second`, and the other program has none either.
  assert.equal("second" in summarizeFixture(fixture).programs[ids[0]].steps["f5-rest"], false);
  assert.equal("second" in summarizeFixture(withSecond).programs[ids[1]].steps["l3-rest"], false);
  // A second row for a step the first recording lacks is refused, not dropped.
  const orphan = structuredClone(fixture);
  orphan.programs[ids[1]].second = { nope: { status: 200, body: [] } };
  assert.throws(() => summarizeFixture(orphan), /second row without a first/);
});

// --- the plan ---

test("the O-8A packet counts are pinned", () => {
  const plan = o6Plan(O8A_PROGRAMS);
  assert.deepEqual(
    {
      programs: plan.programs,
      steps: plan.steps,
      rest: plan.rest,
      grpc: plan.grpc,
      commits: plan.commits,
      seedDocs: plan.seedDocs,
    },
    { programs: 7, steps: 104, rest: 83, grpc: 21, commits: 20, seedDocs: 5562 },
  );
});

test("property: the O-8A plan is additive and matches the runner's ceilings", () => {
  forAll(
    60,
    (random) => {
      const left = [];
      const right = [];
      for (const program of O8A_PROGRAMS) (random() < 0.5 ? left : right).push(program);
      return { left, right };
    },
    ({ left, right }) => {
      const whole = o6Plan([...left, ...right]);
      const a = o6Plan(left);
      const b = o6Plan(right);
      for (const key of ["programs", "steps", "rest", "grpc", "commits", "seedDocs"]) {
        assert.equal(whole[key], a[key] + b[key], key);
      }
      const limits = ceilings([...left, ...right]);
      assert.equal(whole.stepCeiling, limits.maxRequests);
      assert.equal(whole.harnessCeiling, limits.maxHarnessRequests);
    },
  );
  const plan = o6Plan(O8A_PROGRAMS);
  assert.ok(plan.worstRequests <= 700, `${plan.worstRequests}`);
  assert.equal(estimatedUsd(O8A_PROGRAMS, 2), plan.estimatedUsd);
  assert.ok(plan.estimatedUsd < 10);
});

test("the O-8A seed/wipe plan equals a simulated run and the database ends empty", async () => {
  const restOnly = O8A_PROGRAMS.map((program) => ({
    ...program,
    steps: program.steps.filter((s) => (s.transport ?? "rest") === "rest"),
  }));
  const fake = fakeFirestore();
  let out;
  try {
    out = await runCorpus(restOnly, production(), { ...ceilings(restOnly), timeoutMs: 5_000 });
  } finally {
    fake.restore();
  }
  assert.deepEqual(out.failures, []);
  assert.equal(fake.store.size, 0);
  const totals = o6Plan(restOnly);
  assert.equal(totals.harnessExpected, out.harnessRequests);
  assert.equal(totals.expectedRequests, 5 + 2 * (out.requests + out.harnessRequests));
  assert.equal(fake.calls.length, out.requests + out.harnessRequests);
});

/** The frozen table (replaced by the fixture's `corpusDigest` once recorded). */
const FROZEN = [
  [
    "fs-ent-pipeline/o8a/framing-small",
    "585b16eed5cd08d756b25d445be5481256726e73bb7b0b23d4e7de5d53b7090f",
  ],
  [
    "fs-ent-pipeline/o8a/framing-large",
    "e5ba4b23322279cb979ce514a3d7a63aff7f5ba1b26601fcb9843179cc6191f8",
  ],
  [
    "fs-ent-pipeline/o8a/names-main",
    "65adfa507cca9f72434a80174faf98e97b893992ef47a37d5c4d9a9d8a3df41f",
  ],
  [
    "fs-ent-pipeline/o8a/dupquote-main",
    "3423894a9ca150a8158bc2c07c77314512de9a30dcf44a2428cd46ffd481a4e2",
  ],
  [
    "fs-ent-pipeline/o8a/precedence-main",
    "6fbfd7386227c63366cb2bc599a6b0930e9d279a9e9bac90eb898e2ff3513b1c",
  ],
  [
    "fs-ent-pipeline/o8a/nesting-main",
    "295c6c5a0c0843819854c6aa49192c848ee1b5b22813101f9ceec78f4561b5f2",
  ],
  [
    "fs-ent-pipeline/o8a/base64-main",
    "652d0c5fcd058daab0ca2c1a1174d9a6cef79b0f517087061510b8c7de91242a",
  ],
];

test("the O-8A table is the frozen one", () => {
  assert.deepEqual(
    O8A_PROGRAMS.map((p) => [p.id, programDigest(p)]),
    FROZEN,
  );
});

// --- the recorded O-8A rows ---

import { readFileSync } from "node:fs";

const readJson = (name) => JSON.parse(readFileSync(new URL(`../${name}`, import.meta.url), "utf8"));

test("the framing programs are kept as a summary of the recorded rows, not as rows", () => {
  const fixture = readJson("fs-ent-pipeline-production.json");
  const summary = readJson("fs-ent-pipeline-framing.json");
  assert.equal(summary.version, 1);
  assert.deepEqual(Object.keys(summary.programs).toSorted(), [...SUMMARY_ONLY].toSorted());
  for (const id of SUMMARY_ONLY) {
    assert.equal(fixture.programs[id], undefined, `${id} is in the fixture`);
    const program = O8A_PROGRAMS.find((p) => p.id === id);
    const kept = summary.programs[id];
    // The summary is of this corpus: same digest, one entry per step.
    assert.equal(kept.corpusDigest, programDigest(program), id);
    assert.deepEqual(Object.keys(kept.steps).toSorted(), program.steps.map((s) => s.id).toSorted());
    for (const [step, row] of Object.entries(kept.steps)) {
      assert.equal(
        row.units.reduce((n, u) => n + u.results, 0),
        row.results,
        `${id}#${step}`,
      );
    }
  }
  // Both recordings agree on what was read, and a step whose two recordings were cut
  // differently keeps both cuts.
  const small = summary.programs[`${O8A_PREFIX}framing-small`].steps;
  for (const [step, count] of [
    ["f5-rest", 5],
    ["f50-grpc", 50],
    ["f500-rest", 500],
    ["f5000-grpc", 5000],
    ["f5000-limit-rest", 1500],
  ]) {
    assert.equal(small[step].results, count, step);
    if (small[step].second) assert.equal(small[step].second.results, count, `${step} second`);
  }
  assert.ok(
    Object.values(small).some((row) => row.second),
    "no differing second recording kept",
  );
  const large = summary.programs[`${O8A_PREFIX}framing-large`].steps;
  assert.deepEqual(
    [large["l12-rest"].results, large["l3-grpc"].results, large["m30-rest"].results],
    [12, 3, 30],
  );
});

test("the recorded O-8A programs are in the fixture with their own digests and every step", () => {
  const fixture = readJson("fs-ent-pipeline-production.json");
  const recorded = O8A_PROGRAMS.filter((p) => !SUMMARY_ONLY.has(p.id));
  assert.equal(recorded.length, 5);
  for (const program of recorded) {
    const row = fixture.programs[program.id];
    assert.ok(row, program.id);
    assert.equal(row.corpusDigest, programDigest(program), program.id);
    assert.deepEqual(Object.keys(row.steps).toSorted(), program.steps.map((s) => s.id).toSorted());
  }
  // The earlier packets' rows are still there: 28 + O-6's 16 + O-7's 11 + these 5.
  assert.equal(Object.keys(fixture.programs).length, 60);
  // Production answered the duplicate quoted path with a server error, every time (O-5, O-8A).
  const dup = fixture.programs[`${O8A_PREFIX}dupquote-main`].steps;
  for (const id of ["same-1", "same-2", "same-3", "different-values", "swapped-order"]) {
    assert.equal(dup[id].status, 500, id);
  }
  for (const id of ["dotted", "quoted-alone", "plain-pair"]) assert.equal(dup[id].status, 200, id);
});
