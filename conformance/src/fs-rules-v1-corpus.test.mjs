import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  corpusDigest,
  countRequests,
  HARNESS_CAP,
  markerOf,
  PRINCIPALS,
  PROGRAMS,
  programDigest,
  REQUEST_CAP,
  RULESET_IDS,
  RULESETS,
  RULESET_TEXT,
  rulesetSource,
  validateCorpus,
} from "./fs-rules-v1/corpus.mjs";

const DIR = join(import.meta.dirname, "fs-rules-v1");
const rows = (program) => program.steps.filter((s) => !s.publish);

test("the corpus is valid and bounded", () => {
  assert.equal(PROGRAMS.length, 4);
  assert.equal(validateCorpus(PROGRAMS), 4 * 19);
  assert.equal(countRequests(PROGRAMS), 76);
  assert.ok(76 <= REQUEST_CAP);
  assert.ok(
    REQUEST_CAP <= 200 && HARNESS_CAP === 1500,
    "the caps are what the presend packet states",
  );
  assert.deepEqual(RULESET_IDS, ["recursive-v1", "recursive-v2", "path-v1", "path-v2"]);
  assert.deepEqual(Object.keys(PRINCIPALS), ["anon"]);
});

test("every ruleset is a v1 or v2 pair: v1 has no rules_version line at all", () => {
  for (const id of RULESET_IDS) {
    const source = rulesetSource(id);
    const v2 = id.endsWith("-v2");
    assert.equal(source.startsWith("rules_version = '2';\n"), v2, id);
    assert.equal(/rules_version/.test(source), v2, id);
    assert.equal(RULESETS[id].version, v2 ? 2 : 1);
    assert.ok(source.includes(`label == '${markerOf(id)}'`), `${id} carries its own marker`);
  }
  for (const shape of ["recursive", "path"]) {
    const v1 = rulesetSource(`${shape}-v1`).replace(markerOf(`${shape}-v1`), "M");
    const v2 = rulesetSource(`${shape}-v2`).replace(markerOf(`${shape}-v2`), "M");
    assert.equal(
      v2,
      `rules_version = '2';\n${v1}`,
      `${shape}: the control differs by the version line only`,
    );
  }
});

test("the two rule shapes are the ones the assignment names, byte for byte", () => {
  const strip = (id) => rulesetSource(id).replace(markerOf(id), "M");
  assert.equal(
    strip("recursive-v1"),
    [
      "service cloud.firestore {",
      "  match /databases/{database}/documents {",
      "    match /fsr-marker/{label} {",
      "      allow write: if label == 'M';",
      "    }",
      "",
      "    match /{document=**} {",
      "      allow read: if true;",
      "    }",
      "  }",
      "}",
      "",
    ].join("\n"),
  );
  assert.ok(
    strip("path-v1").includes(
      "    match /{path=**}/posts/{d} {\n      allow read: if true;\n    }",
    ),
  );
});

test("marker labels are unique, name their ruleset and follow the source", () => {
  const labels = RULESET_IDS.map(markerOf);
  assert.equal(new Set(labels).size, 4);
  for (const id of RULESET_IDS) assert.match(markerOf(id), new RegExp(`^${id}-[0-9a-f]{12}$`));
  // A marker is a write rule: the recursive read rule would allow any read of a marker document.
  for (const id of RULESET_IDS) assert.match(rulesetSource(id), /allow write: if label == /);
});

test("every program runs the same rows, publication first", () => {
  const ids = (p) => p.steps.map((s) => s.id);
  for (const program of PROGRAMS) {
    assert.deepEqual(ids(program), ids(PROGRAMS[0]));
    assert.deepEqual(program.steps[0], { id: "publishes", publish: true });
  }
  assert.deepEqual(
    PROGRAMS.map((p) => p.ruleset),
    RULESET_IDS,
  );
});

test("the rows cover the finding: group query, COUNT, Listen, controls and kindless queries", () => {
  const byId = Object.fromEntries(rows(PROGRAMS[0]).map((s) => [s.id, s]));
  const from = (id) =>
    byId[id].body?.structuredQuery?.from?.[0] ??
    byId[id].body?.structuredAggregationQuery?.structuredQuery?.from?.[0] ??
    byId[id].query.from[0];
  assert.equal(byId["group-none"].rpc, "runQuery");
  assert.deepEqual(from("group-none"), { collectionId: "posts", allDescendants: true });
  assert.equal(byId["group-count-none"].rpc, "runAggregationQuery");
  assert.deepEqual(from("group-count-none"), { collectionId: "posts", allDescendants: true });
  assert.equal(byId["group-grpc-none"].transport, "grpc");
  assert.equal(byId["group-count-grpc-none"].transport, "grpc");
  assert.equal(byId["group-listen-none"].rpc, "listen");
  assert.equal(byId["group-listen-anon"].as, "anon");
  assert.deepEqual(from("group-listen-none"), { collectionId: "posts", allDescendants: true });
  // Controls: the same collection without allDescendants, and plain gets.
  assert.deepEqual(from("single-none"), { collectionId: "posts" });
  assert.deepEqual(from("single-listen-none"), { collectionId: "posts" });
  assert.equal(byId["nested-none"].parent, "fsr-g1/x");
  assert.equal(byId["get-top-none"].rpc, "get");
  // Kindless: allDescendants without a collection id, under a parent document and at the root.
  assert.deepEqual(from("kindless-parent-none"), { allDescendants: true });
  assert.equal(byId["kindless-parent-none"].parent, "fsr-g1/x");
  assert.deepEqual(from("kindless-root-none"), { allDescendants: true });
  assert.equal(byId["kindless-root-none"].parent, undefined);
  assert.equal(byId["kindless-count-parent-none"].rpc, "runAggregationQuery");
  // Unauthenticated and signed-in rows exist, and no other principal.
  const principals = new Set(rows(PROGRAMS[0]).map((s) => s.as));
  assert.deepEqual([...principals].toSorted(), ["anon", "none"]);
});

test("program digests are per program and follow the rulesets", () => {
  const digests = PROGRAMS.map(programDigest);
  assert.equal(new Set(digests).size, 4);
  for (const digest of digests) assert.match(digest, /^[0-9a-f]{64}$/);
  assert.match(corpusDigest(), /^[0-9a-f]{64}$/);
  assert.notEqual(corpusDigest(PROGRAMS.slice(1)), corpusDigest());
});

test("the corpus names no sandbox, no address, no number and no absolute path", () => {
  const text = JSON.stringify(PROGRAMS) + RULESET_IDS.map(rulesetSource).join("\n");
  assert.ok(!/fireemu-oracle|fireemu-35fe6|@|\d{9,}|\/Users\/|\/home\//.test(text));
});

test("the committed sources of the recorder hold no home-directory path and one project", () => {
  for (const file of readdirSync(DIR)) {
    const text = readFileSync(join(DIR, file), "utf8");
    assert.ok(!/\/Users\/|\/home\/|docs\.local/.test(text), `${file}: a machine-local path`);
    assert.ok(
      !/fireemu-35fe6|fireemu-oracle-sbx|fireemu-oracle-query|fireemu-fs-bisect|\d{12}/.test(
        text.replace(/123456789012|555500000001/g, ""),
      ),
      `${file}: another project or a number`,
    );
  }
});

test("only the sandbox identifier and the production hosts are literals of the runner", () => {
  const code = [
    "run.mjs",
    "session.mjs",
    "grpc.mjs",
    "corpus.mjs",
    "judge.mjs",
    "record.mjs",
    "preflight.mjs",
  ]
    .map((f) => readFileSync(join(DIR, f), "utf8"))
    .join("\n");
  const hosts = [...code.matchAll(/https?:\/\/[^\s"'`)]+/g)].map((m) => m[0]);
  // Loopback examples in comments and the token issuer URL are the only literals besides hosts.
  for (const host of hosts)
    assert.ok(
      /googleapis\.com|securetoken\.google\.com|127\.0\.0\.1|localhost|firebase\.google\.com|\$\{process\.env\./.test(
        host,
      ),
      host,
    );
  assert.ok(
    !/projects\/[a-z][a-z0-9-]{5,}\//.test(code.replace(/projects\/\$\{/g, "")),
    "a project id literal",
  );
});

// ---- the static guard: near misses ----------------------------------------------------------

const clone = () => structuredClone(PROGRAMS);
const refuses = (mutate, pattern) => {
  const programs = clone();
  mutate(programs);
  assert.throws(() => validateCorpus(programs), pattern);
};

test("validateCorpus refuses what the corpus must never contain", () => {
  refuses((p) => (p[0].id = "other/x"), /bad program id/);
  refuses((p) => (p[1].id = p[0].id), /duplicate program/);
  refuses((p) => (p[0].ruleset = "recursive-v3"), /unknown ruleset/);
  refuses((p) => (p[0].steps[2].id = p[0].steps[1].id), /duplicate step/);
  refuses((p) => (p[0].steps[1].id = "Bad Id"), /bad step id/);
  refuses((p) => p[0].steps.push(p[0].steps.shift()), /publication is the first step/);
  refuses((p) => (p[0].steps[1].rpc = "delete"), /unknown rpc/);
  refuses((p) => (p[0].steps[1].as = "stranger"), /unknown principal/);
  refuses((p) => (p[0].steps.find((s) => s.rpc === "listen").transport = "rest"), /gRPC only/);
  refuses((p) => (p[0].steps.find((s) => s.rpc === "get").doc = "/abs/path"), /relative/);
  refuses((p) => (p[0].steps.find((s) => s.rpc === "get").doc = "a/../b"), /relative/);
  refuses((p) => (p[0].steps.find((s) => s.rpc === "get").doc = "https://x/y"), /relative/);
  refuses((p) => (p[0].seed[0].doc = "../x"), /seed path must be relative/);
  refuses((p) => (p[0].seed[0].fields.owner = { stringValue: "someone@example.com" }), /address/);
  refuses((p) => (p[0].steps[1].database = "other"), /database/);
});

test("validateCorpus refuses a corpus over the request cap", () => {
  const programs = Array.from({ length: 7 }, (_, i) => ({
    ...structuredClone(PROGRAMS[0]),
    id: `fs-rules-v1/many/p${i}`,
  }));
  assert.equal(countRequests(programs), 7 * 19);
  assert.throws(() => validateCorpus(programs), /request cap \(133 > 120\)/);
  assert.equal(validateCorpus(programs.slice(0, 6)), 6 * 19);
});

test("an unknown ruleset id has no source and the digest covers every ruleset in order", () => {
  assert.throws(() => rulesetSource("nope"), /unknown ruleset nope/);
  assert.throws(() => markerOf("nope"), /unknown ruleset nope/);
  assert.equal(RULESET_TEXT, RULESET_IDS.map(rulesetSource).join("\n"));
});

test("the aggregation rows ask for a COUNT named n, which the console and the judge read", () => {
  const counts = PROGRAMS[0].steps.filter((s) => s.rpc === "runAggregationQuery");
  assert.equal(counts.length, 5);
  for (const step of counts)
    assert.deepEqual(step.body.structuredAggregationQuery.aggregations, [
      { alias: "n", count: {} },
    ]);
});

test("the one principal is an anonymous sign-up", () => {
  assert.deepEqual(PRINCIPALS, { anon: { provider: "anonymous" } });
});
