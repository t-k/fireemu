// The pipeline regex observation (owner decision 2404): what each step asks, that it only reads
// one probe document in the named database, and that the corpus is plain ASCII source. Nothing
// here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { buildRestRequest, guardRestRequest, validateCorpus } from "./fs-ent-pipeline/harness.mjs";
import {
  PAIRS,
  PROBE,
  PROGRAMS,
  REGEX_FUNCTIONS,
  REGEX_LANE,
  REGEX_PREFIX,
  stepIdOf,
} from "./fs-ent-pipeline/regex-corpus.mjs";
import { LANES, selectLane } from "./fs-query-index/lanes.mjs";
import { ceilings, estimatedUsd, programDigest, selectPrograms } from "./fs-query-index/run.mjs";
import { runCorpus } from "./fs-ent-pipeline/session.mjs";
import { o6Plan } from "./fs-ent-pipeline/o6-corpus.mjs";
import { fakeFirestore, production, stagesOf } from "./fs-ent-pipeline/test-support.mjs";

const selectOf = (s) => stagesOf(s).find((t) => t.name === "select").args[0].mapValue.fields;

test("the lane is its own entry and leaves the O-series lane alone", () => {
  assert.equal(REGEX_LANE, "fs-ent-pipeline-regex");
  const lane = LANES[REGEX_LANE];
  assert.equal(lane.id, REGEX_LANE);
  assert.equal(lane.database, "entpipe1");
  assert.equal(lane.edition, "ENTERPRISE");
  assert.equal(lane.harness, "src/fs-ent-pipeline");
  assert.equal(lane.corpus, "../fs-ent-pipeline/regex-corpus.mjs");
  assert.equal(lane.fixture, "fs-ent-pipeline-regex-production.json");
  assert.equal(lane.taskId, "FS-PIPELINE-REGEX");
  assert.equal(lane.localConfig, "fs-ent-pipeline.fireemu.json");
  assert.equal(lane.firebaseJson, "fs-ent-pipeline.firebase.json");
  assert.equal(LANES["fs-ent-pipeline"].fixture, "fs-ent-pipeline-production.json");
  assert.equal(LANES["fs-ent-pipeline"].taskId, "FS-ENT-ORACLE");
  assert.equal(selectLane("fs-ent-pipeline-regex").id, REGEX_LANE);
  // The emulator twin runs the same corpus against the emulator profile.
  const twin = LANES[`${REGEX_LANE}-emulator`];
  assert.equal(twin.localConfig, "fs-ent-pipeline.emulator.fireemu.json");
  assert.equal(twin.id, REGEX_LANE);
  assert.equal(twin.fixture, lane.fixture);
});

test("programs are valid, uniquely named under the lane prefix, and selected by it", () => {
  assert.ok(PROGRAMS.length >= 5);
  assert.equal(validateCorpus(PROGRAMS, REGEX_LANE) > 0, true);
  for (const p of PROGRAMS) assert.ok(p.id.startsWith(REGEX_PREFIX), p.id);
  assert.deepEqual(selectPrograms(PROGRAMS, REGEX_PREFIX), PROGRAMS);
  assert.equal(new Set(PROGRAMS.map(programDigest)).size, PROGRAMS.length);
});

test("every pair is asked of all four regex functions, in one program, subject then pattern", () => {
  assert.deepEqual(REGEX_FUNCTIONS, [
    "regex_contains",
    "regex_match",
    "regex_find",
    "regex_find_all",
  ]);
  const byId = new Map(PROGRAMS.flatMap((p) => p.steps.map((s) => [`${p.id}#${s.id}`, s])));
  assert.equal(byId.size, PAIRS.length * 4);
  for (const pair of PAIRS) {
    const program = PROGRAMS.find((p) => p.id === `${REGEX_PREFIX}rx/${pair.group}`);
    assert.ok(program, pair.group);
    for (const name of REGEX_FUNCTIONS) {
      const s = program.steps.find((t) => t.id === stepIdOf(name, pair.label));
      assert.ok(s, `${name} ${pair.label}`);
      assert.deepEqual(
        stagesOf(s).map((t) => t.name),
        ["collection", "select"],
      );
      assert.deepEqual(Object.keys(selectOf(s)), ["v"]);
      const call = selectOf(s).v.functionValue;
      assert.equal(call.name, name);
      assert.equal(call.args.length, 2);
      assert.deepEqual(call.args[0], { fieldReferenceValue: pair.subject });
      assert.deepEqual(call.args[1], { stringValue: pair.pattern });
    }
  }
});

test("each program seeds one probe document and reads only that collection", () => {
  for (const p of PROGRAMS) {
    assert.deepEqual(p.seed, [["rx/d1", PROBE]]);
    for (const s of p.steps) {
      assert.equal(s.rpc, "executePipeline");
      assert.equal(s.transport, undefined);
      const collection = stagesOf(s).find((t) => t.name === "collection");
      assert.deepEqual(collection.args, [{ referenceValue: "/rx" }]);
    }
  }
  for (const pair of PAIRS) assert.ok(Object.hasOwn(PROBE, pair.subject), pair.subject);
  for (const [name, value] of Object.entries(PROBE)) {
    assert.match(name, /^[a-z][a-z0-9]*$/);
    assert.deepEqual(Object.keys(value), ["stringValue"]);
  }
});

test("labels are unique, patterns and subjects are never empty, groups are the known six", () => {
  assert.equal(new Set(PAIRS.map((p) => p.label)).size, PAIRS.length);
  for (const p of PAIRS) {
    assert.match(p.label, /^[a-z0-9]+(-[a-z0-9]+)*$/);
    assert.ok(p.pattern.length > 0, p.label);
  }
  assert.deepEqual(
    [...new Set(PAIRS.map((p) => p.group))].toSorted(),
    ["backslash", "capture", "control", "digit", "flag", "space", "word"].toSorted(),
  );
});

test("the issue's named probes are present", () => {
  const get = (label) => PAIRS.find((p) => p.label === label);
  assert.equal(PROBE.ad.stringValue, String.fromCodePoint(0x661, 0x662, 0x663));
  assert.equal(get("d-arabic").pattern, "\\d");
  assert.equal(get("w-eacute").pattern, "\\w");
  assert.equal(PROBE.ead.stringValue, String.fromCodePoint(0xe9));
  assert.equal(get("b-eacute").pattern, "\\b");
  assert.equal(PROBE.nbsp.stringValue, `a${String.fromCodePoint(0xa0)}b`);
  assert.equal(get("s-nbsp").pattern, "a\\sb");
  for (const label of ["nd-arabic", "nw-eacute", "ns-nbsp", "nb-eacute"]) assert.ok(get(label));
  assert.ok(get("u-flag") && get("nu-flag") && get("i-eacute"));
  assert.ok(get("bs-lit") && get("ctl-hex"));
});

test("the source holds ASCII only, so no raw code point can be re-encoded by an editor", () => {
  const text = readFileSync(new URL("./fs-ent-pipeline/regex-corpus.mjs", import.meta.url), "utf8");
  for (const ch of text) assert.ok(ch === "\t" || ch === "\n" || (ch >= " " && ch <= "~"), ch);
});

test("every request stays in the named database, is a pipeline read or a seed, and is guarded", () => {
  const ctx = production();
  for (const p of PROGRAMS) {
    for (const s of p.steps) {
      const request = buildRestRequest(s, ctx, {});
      assert.ok(request.url.endsWith("/databases/entpipe1/documents:executePipeline"), request.url);
      guardRestRequest(request, ctx);
      assert.equal(JSON.parse(request.init.body).structuredPipeline.pipeline.stages.length, 2);
    }
  }
});

test("the request ceilings and the estimate stay far under the task budget", () => {
  const total = PROGRAMS.reduce((n, p) => n + p.steps.length, 0);
  assert.equal(total, PAIRS.length * 4);
  assert.ok(total <= 400);
  assert.equal(ceilings(PROGRAMS).maxRequests, total);
  assert.ok(estimatedUsd(PROGRAMS, 2) < 1);
});

test("the plan of the envelope equals a simulated run against the fake database", async () => {
  const plan = o6Plan(PROGRAMS);
  assert.equal(plan.programs, PROGRAMS.length);
  assert.equal(plan.steps, PAIRS.length * 4);
  assert.equal(plan.grpc + plan.commits, 0);
  assert.equal(plan.seedDocs, PROGRAMS.length);
  assert.equal(estimatedUsd(PROGRAMS, 2), plan.estimatedUsd);
  const limits = ceilings(PROGRAMS);
  const fake = fakeFirestore();
  let out;
  try {
    out = await runCorpus(PROGRAMS, production(), { ...limits, timeoutMs: 5_000 });
  } finally {
    fake.restore();
  }
  assert.deepEqual(out.failures, []);
  assert.equal(fake.store.size, 0);
  assert.equal(plan.harnessExpected, out.harnessRequests);
  assert.equal(plan.expectedRequests, 5 + 2 * (out.requests + out.harnessRequests));
  assert.ok(plan.expectedRequests < 1000);
});
