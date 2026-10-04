import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { compareRuns } from "./functions-events/compare/compare.mjs";
import { createTransport } from "./functions-events/record/rest.mjs";
import { record } from "./functions-events/record/run.mjs";
import { createWorld } from "./functions-events-record-world.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const corpus = read("../functions-events/corpus.json");
const programs = read("../functions-events/programs.json");

async function recordedRun() {
  const clock = { t: Date.UTC(2026, 9, 4) };
  const world = createWorld({ now: () => clock.t });
  const transport = createTransport({
    directory: mkdtempSync(join(tmpdir(), "fe-rc-")),
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
    now: () => clock.t,
  });
  let n = 0;
  const { run } = await record({
    transport,
    cli: async (action) => {
      if (action === "deploy") world.deploy();
      else world.undeploy();
      return { action };
    },
    sleep: async (s) => {
      clock.t += s * 1000;
    },
    now: () => clock.t,
    newId: (role) => `e${String(++n).padStart(6, "0")}${role}`,
    corpusDigest: "0".repeat(64),
  });
  return run;
}

test("the comparator accepts the recorder's run record and attributes every frame it captured", async () => {
  const run = await recordedRun();
  const empty = {
    schemaVersion: 1,
    parent: "FUNCTIONS-EVENTS",
    authority: "LOCAL_ONLY",
    productionEvidence: null,
    programs: [],
  };
  const result = compareRuns({
    corpus,
    programs,
    productionRun: run,
    localSessions: { emulator: empty, strict: empty },
    localProject: "demo-conformance",
  });
  const caseIds = programs.programs.flatMap((program) => program.caseIds);
  assert.equal(result.rows.length, caseIds.length);
  // with no local session every row is INCOMPLETE for want of a local observation, and for no other reason
  // that concerns the production record (its operations, windows and frames all read cleanly)
  const productionReasons = result.rows
    .flatMap((row) => row.reasons)
    .filter((reason) => reason.startsWith("production"));
  assert.deepEqual([...new Set(productionReasons)], []);
  assert.ok(result.rows.every((row) => row.status === "INCOMPLETE"));
});
