import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { evaluateSample } from "./sample-contract.mjs";
const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const requests = read("../../fs-ent-pipeline-requests.json"),
  fixture = read("../../fs-ent-pipeline-production.json"),
  policy = read("./finitepolicy.json");
const program = requests.programs.find((p) => p.id === "fs-ent-pipeline/o8d/stages-main");
const companionRequest = program.steps.find((s) => s.id === "sample-percent-100"),
  companion = fixture.programs[program.id].steps[companionRequest.id];
function input(p) {
  const id = p.id.split("#")[1];
  return {
    id: p.id,
    profile: "strict",
    request: program.steps.find((s) => s.id === id),
    seed: program.seed,
    companionRequest,
    companion,
    response: fixture.programs[program.id].steps[id],
    role: "fixture",
  };
}
test("eight exact production successes meet the finite sample contract", () => {
  assert.equal(policy.recipes.length, 8);
  for (const p of policy.recipes) assert.ok(evaluateSample(input(p)), p.id);
});

import { sampleRows, validTimestamp } from "./sample-contract.mjs";
test("second saved production answers satisfy their exact contracts", () => {
  const second = fixture.programs[program.id].second;
  for (const p of policy.recipes) {
    const id = p.id.split("#")[1];
    if (second[id]) {
      const x = input(p);
      x.response = second[id];
      assert.ok(evaluateSample(x), id);
    }
  }
});
test("timestamp validity and fixture-only placeholders", () => {
  for (const t of [
    "2031-02-03T04:05:06.123456Z",
    "2000-02-29T00:00:00+09:00",
    "0001-01-01T00:00:00Z",
  ])
    assert.equal(validTimestamp(t, "live", "<t1>"), true, t);
  for (const t of [
    "<t1>",
    "2031-02-29T00:00:00Z",
    "2020-01-01",
    "9999-13-01T00:00:00Z",
    "0000-01-01T00:00:00Z",
    "2020-01-01T24:00:00Z",
    "bad",
  ])
    assert.equal(validTimestamp(t, "live", "<t1>"), false, t);
  assert.equal(validTimestamp("<t1>", "fixture", "<t1>"), true);
});
function live(x) {
  const y = structuredClone(x);
  y.role = "live";
  for (const unit of y.response.body) {
    unit.executionTime = "2031-02-03T04:05:06.123456Z";
    for (const r of unit.results ?? []) {
      r.name = r.name.replace("projects/demo-fs-query-index/", "projects/fireemu-oracle-query/");
      r.createTime = "2031-02-03T04:05:06Z";
      r.updateTime = "2031-02-03T04:05:06Z";
    }
  }
  return y;
}
test("live response requires exact bindings, metadata, types, framing and prefix", () => {
  const p = policy.recipes.find((x) => x.id.endsWith("sample-documents-2"));
  const baseline = live(input(p));
  assert.ok(evaluateSample(baseline));
  for (const change of [
    (x) => (x.profile = "ordinary"),
    (x) => (x.id = "unknown"),
    (x) => (x.request.id = "changed"),
    (x) => (x.seed[0][0] = "bad"),
    (x) => (x.seed.at(-1)[1].n.integerValue = "99"),
    (x) => (x.companionRequest.id = "bad"),
    (x) => (x.companion.status = 400),
    (x) => (x.response.status = 400),
    (x) => (x.response.extra = "bad"),
    (x) => x.response.body.push({}),
    (x) => (x.response.body[0].error = {}),
    (x) => delete x.response.body[0].executionTime,
    (x) => (x.response.body[0].executionTime = "<t1>"),
    (x) => (x.response.body[0].executionTime = "2031-02-30T00:00:00Z"),
    (x) => (x.response.body[0].results[0].createTime = "<t2>"),
    (x) => delete x.response.body[0].results[0].updateTime,
    (x) =>
      (x.response.body[0].results[0].name = x.response.body[0].results[0].name.replace(
        "fireemu-oracle-query",
        "other",
      )),
    (x) => (x.response.body[0].results[0].fields.n = { doubleValue: 1 }),
    (x) => x.response.body[0].results.push(structuredClone(x.response.body[0].results[0])),
    (x) => x.response.body[0].results.pop(),
  ]) {
    const y = structuredClone(baseline);
    change(y);
    assert.equal(evaluateSample(y), null);
  }
});
test("percent accepts all subsequence lengths and rejects reordering", () => {
  const p = policy.recipes.find((x) => x.id.endsWith("sample-percent-50")),
    base = live(input(p)),
    src = live({ ...input(p), response: companion }).response.body[0].results;
  for (let n = 0; n <= src.length; n++) {
    const x = structuredClone(base);
    x.response.body[0].results = src.slice(0, n);
    assert.ok(evaluateSample(x), `n=${n}`);
  }
  const x = structuredClone(base);
  x.response.body[0].results = [src[1], src[0]];
  assert.equal(evaluateSample(x), null);
});
test("typed occurrence multisets and nested sequence are preserved", () => {
  const a = { v: { integerValue: "1" } },
    b = { v: { doubleValue: 1 } };
  assert.equal(sampleRows([a, a], [a, b], "documents", 2), false);
  assert.equal(sampleRows([a, b], [a, a, b], "documents", 2), true);
  assert.equal(sampleRows([a, b], [b, a], "percent", 0.5), false);
  assert.equal(
    sampleRows(
      [{ v: { arrayValue: { values: [b, a] } } }],
      [{ v: { arrayValue: { values: [a, b] } } }],
      "documents",
      1,
    ),
    false,
  );
});
test("where and suffix limit retain the exact eligible population", () => {
  const p = policy.recipes.find((x) => x.placement === "where"),
    x = live(input(p)),
    full = live({ ...input(p), response: companion }).response.body[0].results;
  x.response.body[0].results = [
    full.find((r) => r.fields.n.integerValue === "1"),
    full.find((r) => r.fields.n.integerValue === "2"),
  ];
  assert.equal(evaluateSample(x), null);
  const q = policy.recipes.find((x) => x.placement === "limit"),
    y = live(input(q));
  for (const row of full) {
    y.response.body[0].results = [row];
    assert.ok(evaluateSample(y));
  }
  y.response.body[0].results = full.slice(0, 2);
  assert.equal(evaluateSample(y), null);
});

test("bounded generated selections preserve typed multiplicity and ordered subsequences", () => {
  const typed = [
    { integerValue: "1" },
    { doubleValue: 1 },
    { nullValue: null },
    { arrayValue: { values: [{ integerValue: "1" }, { integerValue: "2" }] } },
  ];
  for (let n = 0; n <= 4; n++) {
    const eligible = typed.slice(0, n);
    for (let mask = 0; mask < 1 << n; mask++) {
      const chosen = eligible.filter((_, i) => mask & (1 << i));
      assert.equal(sampleRows(chosen, eligible, "percent", 0.5), true);
      assert.equal(sampleRows(chosen, eligible, "documents", chosen.length), true);
      if (chosen.length > 1)
        assert.equal(sampleRows([...chosen].reverse(), eligible, "percent", 0.5), false);
    }
  }
});

test("live invalid but present updateTime is rejected", () => {
  const p = policy.recipes.find((x) => x.id.endsWith("sample-documents-2"));
  const x = live(input(p));
  assert.ok(evaluateSample(x));
  x.response.body[0].results[0].updateTime = "not-a-timestamp";
  assert.equal(evaluateSample(x), null);
});

import { checkIdentity } from "./sample-contract-binding.mjs";
test("binding rejects missing, repeated and misclassified identities", () => {
  const rows = [
    { row: "a", status: "MATCH" },
    { row: "b", status: "MISMATCH" },
  ];
  assert.equal(checkIdentity(rows, ["a", "b"], { MATCH: 1, MISMATCH: 1 }), true);
  assert.equal(checkIdentity([rows[0], rows[0]], ["a", "b"], { MATCH: 1, MISMATCH: 1 }), false);
  assert.equal(checkIdentity(rows, ["a", "c"], { MATCH: 1, MISMATCH: 1 }), false);
  assert.equal(checkIdentity(rows, ["a", "b"], { MATCH: 2 }), false);
  assert.equal(
    checkIdentity([rows[0], rows[0], rows[1]], ["a", "b", "c"], { MATCH: 2, MISMATCH: 1 }),
    false,
  );
});

import { checkCandidate, rawResponse } from "./sample-contract-binding.mjs";
test("binding rejects unapproved profile, stale source and untrusted index before use", () => {
  assert.throws(
    () =>
      checkCandidate(
        { index: Buffer.from("{}") },
        {
          profile: "ordinary",
          sourceCommit: "8220a36ad88c136592551ebb94f358d6abe4d909",
          indexSha256: "0".repeat(64),
        },
      ),
    /candidate identity/,
  );
  assert.throws(
    () =>
      checkCandidate({}, { profile: "strict", sourceCommit: "other", indexSha256: "a".repeat(64) }),
    /candidate identity/,
  );
  assert.throws(
    () =>
      checkCandidate(
        { index: Buffer.from("{}") },
        {
          profile: "strict",
          sourceCommit: "8220a36ad88c136592551ebb94f358d6abe4d909",
          indexSha256: "0".repeat(64),
        },
      ),
    /index hash/,
  );
});
test("raw REST extraction rejects transport failures and malformed responses", () => {
  assert.deepEqual(rawResponse({ transport: "rest", response: { status: 200, text: "[]" } }), {
    status: 200,
    body: [],
  });
  for (const raw of [
    { transport: "grpc", response: { status: 200, text: "[]" } },
    { transport: "rest", response: { status: 500, text: "[]" } },
    { transport: "rest", response: { status: 200, text: "bad" } },
    { transport: "rest", response: { status: 200, text: "[]", transportError: "bad" } },
  ])
    assert.throws(() => rawResponse(raw));
});

import { checkBuild } from "./sample-contract-binding.mjs";
import { createHash } from "node:crypto";
test("build binding rejects stale binary, source and profile", () => {
  const source = "8220a36ad88c136592551ebb94f358d6abe4d909",
    binary = Buffer.from("binary"),
    digest = createHash("sha256").update(binary).digest("hex"),
    index = { sourceCommit: source, binarySha256: digest },
    receipt = { sourceCommit: source, binarySha256: digest };
  assert.equal(checkBuild(index, receipt, binary, digest, "profile: strict"), true);
  assert.equal(checkBuild(index, receipt, Buffer.from("other"), digest, "profile: strict"), false);
  assert.equal(
    checkBuild({ ...index, sourceCommit: "stale" }, receipt, binary, digest, "profile: strict"),
    false,
  );
  assert.equal(checkBuild(index, receipt, binary, digest, "profile: emulator"), false);
});

import { checkConfig } from "./sample-contract-binding.mjs";
test("candidate configuration must bind strict enterprise native mode", () => {
  const config = {
    profile: "strict",
    productionExact: true,
    firestore: { edition: "enterprise", apiMode: "native" },
  };
  assert.equal(checkConfig(config), true);
  for (const value of [
    { ...config, profile: "emulator" },
    { ...config, productionExact: false },
    { ...config, firestore: { edition: "standard", apiMode: "native" } },
    { ...config, firestore: { edition: "enterprise", apiMode: "datastore" } },
  ])
    assert.equal(checkConfig(value), false);
});
