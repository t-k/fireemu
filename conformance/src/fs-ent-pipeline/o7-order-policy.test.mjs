import { test } from "node:test";
import assert from "node:assert/strict";
import { compareBag, subset } from "./o7-order-policy.mjs";
const a = { fields: { v: { integerValue: "1" } } },
  b = { fields: { v: { doubleValue: 1 } } };
test("typed bag ignores outer order but keeps multiplicity and types", () => {
  assert.equal(compareBag([a, b], [b, a]), true);
  assert.equal(compareBag([a, a], [a, b]), false);
  assert.equal(compareBag([a, a, b], [a, b, b]), false);
  assert.equal(compareBag([a], [b]), false);
  assert.equal(
    compareBag(
      [{ fields: { v: { arrayValue: { values: [a, b] } } } }],
      [{ fields: { v: { arrayValue: { values: [b, a] } } } }],
    ),
    false,
  );
});
test("selection requires exact cardinality and multiplicity", () => {
  assert.equal(subset([a], [a, b], 1), true);
  assert.equal(subset([a, a], [a, b], 2), false);
  assert.equal(subset([a], [a, b], 2), false);
});

import { readFileSync } from "node:fs";
import { evaluate } from "./o7-order-policy.mjs";
const load = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const policy = load("./o7-order-policy-data.json"),
  req = load("../../fs-ent-pipeline-requests.json"),
  fixture = load("../../fs-ent-pipeline-production.json");
function args(p) {
  const [id, step] = p.id.split("#"),
    program = req.programs.find((x) => x.id === id),
    production = fixture.programs[id].steps[step];
  const x = {
    id: p.id,
    profile: "strict",
    rawStatus: "MISMATCH",
    request: program.steps.find((x) => x.id === step),
    seed: program.seed,
    production,
    production2: production,
    local: production,
  };
  if (p.companion) {
    const [cp, cs] = p.companion.split("#");
    x.companionRequest = req.programs.find((x) => x.id === cp).steps.find((x) => x.id === cs);
    x.companionProduction = fixture.programs[cp].steps[cs];
    x.companionProduction2 = x.companionProduction;
    x.companionLocal = x.companionProduction;
  }
  return x;
}
test("all exact policy recipes pass their recorded typed witnesses", () => {
  assert.equal(policy.recipes.length, 23);
  for (const p of policy.recipes) assert.ok(evaluate(args(p)), p.id);
});
test("binding, profile, status, result shape and typed content reject changes", () => {
  const p = policy.recipes.find((x) => x.mode === "full" && !x.sort);
  const orig = args(p);
  for (const change of [
    (x) => (x.profile = "ordinary"),
    (x) => (x.id = policy.unresolved[0]),
    (x) => (x.request.id = "other"),
    (x) => (x.seed[0][0] = "other"),
    (x) => (x.production.status = 400),
    (x) => (x.production2.status = 400),
    (x) => (x.local.status = 400),
    (x) => x.local.body.push({}),
    (x) => x.local.body[0].results.push(structuredClone(x.local.body[0].results[0])),
    (x) => (x.local.body[0].results[0].fields = { bad: { integerValue: "1" } }),
  ]) {
    const x = structuredClone(orig);
    change(x);
    assert.equal(evaluate(x), null);
  }
});
test("selection checks companion binding, membership, multiplicity, alias collision and count", () => {
  for (const p of policy.recipes.filter((x) => x.mode === "selection")) {
    const orig = args(p);
    for (const change of [
      (x) => (x.companionRequest.id = "other"),
      (x) => x.companionLocal.body[0].results.pop(),
      (x) => x.local.body[0].results.pop(),
      (x) => (x.local.body[0].results[0].fields = { foreign: { integerValue: "9" } }),
      (x) => (x.local.body[0].results[0] = structuredClone(x.local.body[0].results[1])),
    ]) {
      const x = structuredClone(orig);
      change(x);
      assert.equal(evaluate(x), null, p.id);
    }
  }
  const p = policy.recipes.find((x) => x.companionAliasRename);
  const x = structuredClone(args(p));
  x.companionLocal.body[0].results[0].fields.c = { integerValue: "1" };
  assert.equal(evaluate(x), null);
});
test("descending sort checks all unequal keys", () => {
  const p = policy.recipes.find((x) => x.sort),
    x = structuredClone(args(p));
  x.local.body[0].results[0].fields.c.integerValue = "2";
  assert.equal(evaluate(x), null);
});

import { verifyIdentity } from "./o7-order-binding.mjs";
test("binding requires unique exact identities and all raw counts", () => {
  const rows = [
    { row: "a", status: "MATCH" },
    { row: "b", status: "MISMATCH" },
  ];
  assert.equal(verifyIdentity(rows, ["a", "b"], { MATCH: 1, MISMATCH: 1 }), true);
  assert.equal(verifyIdentity([rows[0], rows[0]], ["a", "b"], { MATCH: 1, MISMATCH: 1 }), false);
  assert.equal(verifyIdentity(rows, ["a", "c"], { MATCH: 1, MISMATCH: 1 }), false);
  assert.equal(verifyIdentity(rows, ["a", "b"], { MATCH: 2 }), false);
});

import { sorted } from "./o7-order-policy.mjs";
import { verifyBytes, descriptorMatches } from "./o7-order-binding.mjs";
test("sort guard accepts descending and ties and rejects an inversion with identical bag", () => {
  const v = (n) => ({ fields: { c: { integerValue: String(n) } } });
  assert.equal(sorted([v(3), v(2), v(2), v(1)]), true);
  assert.equal(sorted([v(3), v(2), v(1), v(2)]), false);
  assert.equal(compareBag([v(3), v(2), v(2), v(1)], [v(3), v(2), v(1), v(2)]), true);
});
test("binding rejects changed bytes and malformed digest", () => {
  const bytes = Buffer.from("abc");
  assert.equal(
    verifyBytes(bytes, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    true,
  );
  assert.equal(
    verifyBytes(
      Buffer.from("abd"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    false,
  );
  assert.equal(verifyBytes(bytes, "invalid"), false);
});
test("descriptor rejects missing or altered dependency binding", () => {
  const fake = {
    bindings: { fixtureSha256: "f", requestExportSha256: "r" },
    outerOrderEquivalenceRecipes: [],
    selectionCompanionProofs: [],
    excludedUnresolvedErrorRecipeIds: [],
  };
  const data = { fixtureSha256: "f", requestExportSha256: "r", recipes: [], unresolved: [] };
  assert.equal(descriptorMatches(data, fake), true);
  data.requestExportSha256 = "x";
  assert.equal(descriptorMatches(data, fake), false);
});
