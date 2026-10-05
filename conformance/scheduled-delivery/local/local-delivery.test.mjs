// The strict profile against the recording, end to end: a real `fireemu exec` with the recorded fixture, a pinned
// logical clock and the recorded digest. Needs a fireemu binary, a Node 22 and firebase-functions 7.3.2:
//
//   FIREEMU_BIN=<bin> FIREEMU_NODE=<node22> FIREEMU_DEPS=<node_modules> node --test local-delivery.test.mjs
//
// Without them the tests are skipped (the unit tests of the comparison need none of it).
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadDigest, rows } from "./compare.mjs";
import { INFLIGHT_RUN, logicalSlowHandler } from "./inflight.mjs";
import { runLocal } from "./local-run.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const { FIREEMU_BIN: fireemu, FIREEMU_NODE: node, FIREEMU_DEPS: depsDir } = process.env;
const live = fireemu && node && depsDir ? test : test.skip;
const production = loadDigest(join(here, "production-run2.json"));
const patch = (source) =>
  source.replace("setTimeout(resolve, 100_000)", "setTimeout(resolve, 100)");
const run = (profile) =>
  runLocal({
    fireemu,
    node,
    depsDir,
    fixtureDir: join(here, "..", "fixture"),
    profile,
    start: "2026-10-05T08:40:30Z",
    seconds: 330,
    patch,
  });

// What strict now matches (recorded in run 156715222b86ea44) and the emulator profile, unchanged, does not.
const DELIVERY = [
  "v2.request.method",
  "v2.request.url",
  "v2.request.headers",
  "v2.request.body",
  "v2.event.keys",
  "v2.event.jobName",
  "v2.event.scheduleTime-form",
  "v2.event.context",
  "v2.event.context-values",
  "v1.argumentCount",
  "v1.context.eventId",
  "v1.context.resource",
  "v1.context.timestamp",
  "v1.context.keys",
  "v1.failure-no-retry",
  "cadence.every-1-minutes.spacing",
];

live("strict: the delivery rows the recording determines all match", async () => {
  const result = await run("strict");
  assert.equal(result.exitCode, 0, result.output.slice(-800));
  const verdicts = Object.fromEntries(
    rows(production, { natural: result, probe: { lines: [] } }).map((r) => [r.id, r.verdict]),
  );
  for (const id of DELIVERY) assert.equal(verdicts[id], "MATCH", id);
});

live(
  "emulator: scheduled invocations are unchanged (the resource name, UTC time, a direct handler call)",
  async () => {
    const result = await run("emulator");
    assert.equal(result.exitCode, 0, result.output.slice(-800));
    const verdicts = Object.fromEntries(
      rows(production, { natural: result, probe: { lines: [] } }).map((r) => [r.id, r.verdict]),
    );
    for (const id of [
      "v2.event.jobName",
      "v2.event.scheduleTime-form",
      "v2.event.context",
      "v1.context.eventId",
      "v1.context.resource",
    ])
      assert.equal(verdicts[id], "DIVERGES", id);
    for (const id of ["v2.event.keys", "v1.argumentCount", "v1.failure-no-retry"])
      assert.equal(verdicts[id], "MATCH", id);
  },
);

const inflight = (profile) =>
  runLocal({
    fireemu,
    node,
    depsDir,
    fixtureDir: join(here, "..", "fixture"),
    profile,
    start: "2026-10-05T08:40:30Z",
    patch: logicalSlowHandler,
    ...INFLIGHT_RUN,
  });
const inflightRow = (result) =>
  rows(production, {
    natural: { lines: [] },
    probe: { lines: [] },
    inflight: result,
  }).find((r) => r.id === "cadence.in-flight-skip");

live(
  "strict: an occurrence is skipped while the slow handler runs, and a manual run still starts",
  async () => {
    const result = await inflight("strict");
    assert.equal(result.exitCode, 0, result.output.slice(-800));
    const row = inflightRow(result);
    assert.deepEqual(row.local, row.production, JSON.stringify(row.local));
    assert.equal(row.verdict, "MATCH");
  },
);

live("emulator: occurrences overlap a running handler, as before", async () => {
  const result = await inflight("emulator");
  assert.equal(result.exitCode, 0, result.output.slice(-800));
  const row = inflightRow(result);
  assert.ok(row.local.naturalStartsInFlight > 0, JSON.stringify(row.local));
  assert.equal(row.local.occurrencesSkipped, false);
  assert.equal(row.verdict, "DIVERGES");
});
