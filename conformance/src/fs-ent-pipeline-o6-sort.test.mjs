// Synthetic counterexamples/property inputs use the original public fixtures, not new observations.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { evaluate } from "./fs-ent-pipeline/o6-sort-policy.mjs";
const requests = JSON.parse(
  readFileSync(new URL("../fs-ent-pipeline-requests.json", import.meta.url)),
).programs;
const fixture = JSON.parse(
  readFileSync(new URL("../fs-ent-pipeline-production.json", import.meta.url)),
).programs;
const clone = (x) => structuredClone(x);
export function inputFor(kind) {
  const id = "fs-ent-pipeline/o6/" + (kind === "v-desc" ? "sort-kinds-cross" : "sort-ties"),
    step = kind === "v-desc" ? "v-desc" : "g-asc-limit2",
    program = requests.find((p) => p.id === id),
    saved = fixture[id];
  const input = {
    id: id + "#" + step,
    profile: "strict",
    rawStatus: "MISMATCH",
    request: clone(program.steps.find((x) => x.id === step)),
    seed: clone(program.seed),
    production: clone(saved.steps[step]),
    production2: clone(saved.second?.[step] ?? saved.steps[step]),
    local: clone(saved.steps[step]),
  };
  if (kind === "v-desc") {
    input.preludeRequest = clone(program.steps.find((x) => x.id === "seed-vector"));
    input.preludeProduction = clone(saved.steps["seed-vector"]);
    input.preludeLocal = clone(saved.steps["seed-vector"]);
    [input.local.body[0].results[14], input.local.body[0].results[15]] = [
      input.local.body[0].results[15],
      input.local.body[0].results[14],
    ];
  } else {
    input.companionRequest = clone(program.steps.find((x) => x.id === "g-asc"));
    input.companionProduction = clone(saved.steps["g-asc"]);
    input.companionProduction2 = clone(saved.second?.["g-asc"] ?? saved.steps["g-asc"]);
    input.companionLocal = clone(saved.steps["g-asc"]);
    input.local.body[0].results = clone([
      input.companionProduction.body[0].results[0],
      input.companionProduction.body[0].results[2],
    ]);
  }
  return input;
}
function fault(input, name) {
  const rows = input.local.body[0].results;
  if (name === "order") {
    if (input.id.endsWith("#v-desc")) [rows[0], rows[1]] = [rows[1], rows[0]];
    else input.companionLocal.body[0].results.reverse();
  }
  if (name === "type") {
    const row = rows.find((x) =>
      Object.values(x.fields ?? {}).some((v) => Object.hasOwn(v, "integerValue")),
    );
    const key = Object.keys(row.fields).find((k) => Object.hasOwn(row.fields[k], "integerValue"));
    row.fields[key] = { doubleValue: Number(row.fields[key].integerValue) };
  }
  if (name === "count") rows.pop();
  if (name === "duplicate") rows[1] = clone(rows[0]);
  if (name === "ineligible")
    rows[0] = input.id.endsWith("#v-desc")
      ? clone(rows[1])
      : clone(
          input.companionProduction.body[0].results.find((x) => x.fields.g.integerValue === "2"),
        );
  if (name === "key")
    input.request.body.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields.expression.fieldReferenceValue =
      "other";
  if (name === "direction")
    input.request.body.structuredPipeline.pipeline.stages[1].args[0].mapValue.fields.direction.stringValue =
      "wrong";
  if (name === "source")
    input.production2.body[0].results[0].fields.unobserved = { booleanValue: true };
}
test("only the two strict owner2114 outcomes admit full typed proofs and preserve input", () => {
  for (const kind of ["v-desc", "limit2"]) {
    const input = inputFor(kind),
      before = JSON.stringify(input),
      out = evaluate(input);
    assert.ok(out, kind);
    assert.equal(out.rawStatus, "MISMATCH");
    assert.equal(out.authority, "owner2114");
    assert.equal(out.resultCount, kind === "v-desc" ? 16 : 2);
    assert.equal(JSON.stringify(input), before);
  }
});
test("non-tie order, typed content, counts, duplicate/ineligible selection and wrong key/source all refuse", () => {
  for (const kind of ["v-desc", "limit2"])
    for (const name of [
      "order",
      "type",
      "count",
      "duplicate",
      "ineligible",
      "key",
      "direction",
      "source",
    ]) {
      const input = inputFor(kind);
      fault(input, name);
      assert.equal(evaluate(input), null, kind + "/" + name);
    }
});
test("profile, unknown identity, shell, seed, prelude and companion source binding are closed", () => {
  for (const kind of ["v-desc", "limit2"])
    for (const name of ["profile", "identity", "status", "shell", "seed", "dependency"]) {
      const input = inputFor(kind);
      if (name === "profile") input.profile = "emulator";
      if (name === "identity") input.id += "-other";
      if (name === "status") input.rawStatus = "MATCH";
      if (name === "shell") input.local.body[0].executionTime = "<different>";
      if (name === "seed") input.seed[0][1].unobserved = { integerValue: "1" };
      if (name === "dependency") {
        if (kind === "v-desc") input.preludeRequest.body.writes = [];
        else input.companionProduction2.body[0].results.pop();
      }
      assert.equal(evaluate(input), null, kind + "/" + name);
    }
});
test("derived minimum-class candidates cannot be duplicated or supplied as a new observed reply", () => {
  const input = inputFor("limit2");
  input.companionLocal.body[0].results[1] = clone(input.companionLocal.body[0].results[0]);
  assert.equal(evaluate(input), null);
  const out = evaluate(inputFor("limit2"));
  assert.equal(out.eligibleCount, 3);
  assert.equal(out.eligibleOrigin, "DERIVED_FROM_BOUND_EXISTING_COMPANION_AND_SEED");
});
test("generated legal tie permutations and all six ordered distinct selections preserve acceptance", () => {
  const cross = inputFor("v-desc"),
    tail = clone(cross.production.body[0].results.slice(14));
  for (const order of [
    [0, 1],
    [1, 0],
  ]) {
    cross.local.body[0].results.splice(14, 2, ...order.map((i) => clone(tail[i])));
    assert.ok(evaluate(cross), `tie permutation ${order}`);
  }
  const input = inputFor("limit2"),
    eligible = input.companionProduction.body[0].results.filter(
      (x) => x.fields.g.integerValue === "1",
    );
  let count = 0;
  for (let a = 0; a < 3; a++)
    for (let b = 0; b < 3; b++)
      if (a !== b) {
        input.local.body[0].results = clone([eligible[a], eligible[b]]);
        assert.ok(evaluate(input), `selection ${a},${b}`);
        count++;
      }
  assert.equal(count, 6);
});
const pictRows = [
  ["v-desc", "strict", "none"],
  ["limit2", "strict", "none"],
  ["v-desc", "strict", "order"],
  ["v-desc", "strict", "type"],
  ["limit2", "strict", "duplicate"],
  ["limit2", "strict", "ineligible"],
  ["limit2", "strict", "key"],
  ["v-desc", "strict", "source"],
  ["v-desc", "emulator", "none"],
  ["limit2", "emulator", "count"],
  ["limit2", "emulator", "type"],
  ["v-desc", "emulator", "key"],
  ["v-desc", "emulator", "ineligible"],
  ["v-desc", "emulator", "duplicate"],
  ["limit2", "emulator", "source"],
  ["limit2", "emulator", "order"],
  ["v-desc", "strict", "count"],
];
test("all generated PICT rows drive the same two-case pure policy", () => {
  for (const [kind, profile, name] of pictRows) {
    const input = inputFor(kind);
    input.profile = profile;
    if (name !== "none") fault(input, name);
    const accepted = profile === "strict" && name === "none";
    assert.equal(Boolean(evaluate(input)), accepted, [kind, profile, name].join("/"));
  }
});
