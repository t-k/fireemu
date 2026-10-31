import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classifySampleContract } from "./fs-query-index/run.mjs";
import { createContext, normalizeStep, resolveValue } from "./fs-ent-pipeline/harness.mjs";
import * as sampleTools from "./fs-ent-pipeline/sample-contract.mjs";
const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const requests = read("../fs-ent-pipeline-requests.json");
const fixture = read("../fs-ent-pipeline-production.json");
const program = requests.programs.find((p) => p.id === "fs-ent-pipeline/o8d/stages-main");
const saved = fixture.programs[program.id];
const step = program.steps.find((s) => s.id === "sample-documents-2");
const production = saved.steps[step.id];
const rawBody = structuredClone(production.body);
for (const u of rawBody) {
  u.executionTime = "2031-02-03T04:05:06Z";
  for (const r of u.results ?? []) {
    r.name = r.name.replace("projects/demo-fs-query-index/", "projects/fireemu-oracle-query/");
    r.createTime = r.updateTime = "2031-02-03T04:05:05Z";
  }
}
const ctx = createContext({
  run: "1",
  startedMs: Date.parse("2031-02-03T04:05:06Z"),
  database: "entpipe1",
  target: { kind: "local", origin: "http://127.0.0.1:1", grpcHost: "127.0.0.1", grpcPort: 1 },
});
const raw = {
  transport: "rest",
  request: resolveValue(step.body, ctx, new Map()),
  response: { status: 200, text: JSON.stringify(rawBody) },
};
const args = {
  status: "MISMATCH",
  lane: "fs-ent-pipeline",
  profile: "strict",
  program,
  step,
  saved,
  production,
  alternative: saved.second?.[step.id],
  fireemu: normalizeStep(raw, ctx, new Map()),
  raw,
  ctx,
  sampleTools,
};
test("finite sample policy is applied only to supported, bound successes", () => {
  assert.equal(classifySampleContract(args).status, "MATCH_NONDETERMINISTIC");
  for (const status of ["UNKNOWN", "STALE_FIXTURE", "MISSING", "INDETERMINATE"])
    assert.equal(classifySampleContract({ ...args, status }).status, status);
  assert.equal(classifySampleContract({ ...args, profile: "emulator" }).status, "MISMATCH");
  assert.equal(classifySampleContract({ ...args, raw: undefined }).status, "MISMATCH");
  assert.equal(
    classifySampleContract({ ...args, raw: { ...raw, response: { status: 500, text: "[]" } } })
      .status,
    "MISMATCH",
  );
  assert.equal(
    classifySampleContract({ ...args, step: { ...step, id: "other" } }).status,
    "MISMATCH",
  );
});

const pictRows = [
  ["documents2", "valid", "complete", "rest"],
  ["percent50", "valid", "complete", "rest"],
  ["documents10", "wrongtype", "missing", "rest"],
  ["where", "missing", "stale", "rest"],
  ["documents10", "changed", "unknown", "rest"],
  ["where", "valid", "unknown", "rest"],
  ["limit", "missing", "missing", "rest"],
  ["documents2", "missing", "unknown", "rest"],
  ["documents10", "missing", "complete", "rest"],
  ["percent50", "missing", "unknown", "rest"],
  ["documents10", "duplicate", "stale", "rest"],
  ["documents2", "changed", "stale", "rest"],
  ["limit", "duplicate", "complete", "rest"],
  ["limit", "changed", "missing", "rest"],
  ["percent50", "wrongtype", "stale", "rest"],
  ["where", "wrongtype", "complete", "rest"],
  ["documents2", "duplicate", "missing", "rest"],
  ["documents2", "wrongtype", "unknown", "rest"],
  ["limit", "wrongtype", "stale", "rest"],
  ["percent50", "duplicate", "missing", "rest"],
  ["percent50", "changed", "complete", "rest"],
  ["documents10", "valid", "missing", "rest"],
  ["limit", "valid", "stale", "rest"],
  ["limit", "duplicate", "unknown", "rest"],
  ["where", "duplicate", "missing", "rest"],
  ["where", "changed", "stale", "rest"],
];

test("seeded PICT rows exercise the finite public sample path", () => {
  const ids = {
    documents2: "sample-documents-2",
    documents10: "sample-documents-10",
    percent50: "sample-percent-50",
    where: "sample-after-where",
    limit: "sample-then-limit",
  };
  for (const [kind, shape, evidence] of pictRows) {
    const selected = program.steps.find((item) => item.id === ids[kind]);
    const prod = saved.steps[selected.id];
    const body = structuredClone(prod.body);
    for (const unit of body) {
      unit.executionTime = "2031-02-03T04:05:06Z";
      for (const doc of unit.results ?? []) {
        doc.name = doc.name.replace(
          "projects/demo-fs-query-index/",
          "projects/fireemu-oracle-query/",
        );
        doc.createTime = doc.updateTime = "2031-02-03T04:05:05Z";
      }
    }
    const docs = body[0].results;
    if (shape === "changed") docs[0].fields.n.integerValue = "999";
    if (shape === "wrongtype") docs[0].fields.n = { stringValue: "1" };
    if (shape === "duplicate") docs.push(structuredClone(docs[0]));
    if (shape === "missing") body[0].results = [];
    const capture = {
      transport: "rest",
      request: resolveValue(selected.body, ctx, new Map()),
      response: { status: 200, text: JSON.stringify(body) },
    };
    const status =
      evidence === "stale" ? "STALE_FIXTURE" : evidence === "unknown" ? "UNKNOWN" : "MISMATCH";
    const out = classifySampleContract({
      ...args,
      status,
      step: selected,
      production: prod,
      alternative: saved.second?.[selected.id],
      raw: evidence === "missing" ? undefined : capture,
      fireemu: normalizeStep(capture, ctx, new Map()),
    });
    const valid = shape === "valid" || (kind === "percent50" && shape === "missing");
    const expected =
      status !== "MISMATCH"
        ? status
        : evidence === "missing" || !valid
          ? "MISMATCH"
          : "MATCH_NONDETERMINISTIC";
    assert.equal(out.status, expected, `${kind}/${shape}/${evidence}`);
  }
});

test("sample evidence must bind request, production and the actual normalized response", () => {
  assert.equal(
    classifySampleContract({ ...args, raw: { ...raw, request: { changed: true } } }).status,
    "MISMATCH",
  );
  const corruptProduction = structuredClone(production);
  corruptProduction.body[0].results[0].fields.n.integerValue = "999";
  assert.equal(
    classifySampleContract({ ...args, production: corruptProduction }).status,
    "MISMATCH",
  );
  const changed = structuredClone(args.fireemu);
  changed.body[0].results.reverse();
  assert.equal(classifySampleContract({ ...args, fireemu: changed }).status, "MISMATCH");
  const outside = structuredClone(rawBody);
  outside[0].executionTime = "2031-02-04T04:05:06Z";
  const outsideRaw = { ...raw, response: { status: 200, text: JSON.stringify(outside) } };
  assert.equal(
    classifySampleContract({
      ...args,
      raw: outsideRaw,
      fireemu: normalizeStep(outsideRaw, ctx, new Map()),
    }).status,
    "MISMATCH",
  );
});

test("live timestamp validation rejects a calendar date that normalizes to a placeholder", () => {
  const invalidBody = structuredClone(rawBody);
  invalidBody[0].executionTime = "2031-02-30T04:05:06Z";
  for (const doc of invalidBody[0].results)
    doc.createTime = doc.updateTime = "2031-03-01T04:05:06Z";
  const invalidRaw = { ...raw, response: { status: 200, text: JSON.stringify(invalidBody) } };
  const shifted = createContext({
    run: "1",
    startedMs: Date.parse("2031-03-02T04:05:06Z"),
    database: "entpipe1",
    target: { kind: "local", origin: "http://127.0.0.1:1", grpcHost: "127.0.0.1", grpcPort: 1 },
  });
  assert.equal(
    classifySampleContract({
      ...args,
      ctx: shifted,
      raw: invalidRaw,
      fireemu: normalizeStep(invalidRaw, shifted, new Map()),
    }).status,
    "MISMATCH",
  );
});
