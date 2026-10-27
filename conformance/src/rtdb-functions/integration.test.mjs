// The whole CV14 run on fakes of every service: the real flow, target operations, upload helper, RTDB
// administration, inventory and judge against a fake of the Google APIs, the RTDB and the Firebase CLI.
// What it shows is the order and the bookkeeping of a run, never what production does.

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { PROJECT } from "../../functions-http/harness.mjs";
import { FIXTURE_HANDLERS, PREFIX } from "./frames.mjs";
import { runStage2 } from "./flow.mjs";
import { assembleStage2 } from "./assemble.mjs";
import { STAGE2_KINDS, STAGE2_LIMITS } from "./wiring.mjs";
import { createRehearsalEnvironment } from "./world.fake.mjs";
import { STEPS } from "./sequence.mjs";

async function setup(arg = {}) {
  const dir = await mkdtemp(join(tmpdir(), "cv14-integration-"));
  const rehearsal = createRehearsalEnvironment(arg);
  const { environment } = rehearsal;
  const journal = [];
  const assembled = assembleStage2({
    ...environment,
    packet: environment.rtdbPacket,
    runDir: dir,
    log: async (action, detail) => journal.push([action, detail]),
  });
  return { dir, ...rehearsal, journal, assembled };
}

const run = (env) => runStage2(env.assembled.deps);
const finish = async (env) => {
  env.assembled.uploads.close();
  await rm(env.dir, { recursive: true, force: true });
};

test("a clean run: eight deploys, nine writes, every documented event seen once, everything removed again", async () => {
  const env = await setup();
  try {
    const result = await run(env);
    assert.equal(result.outcome, "recorded", result.reasons.join("; "));
    assert.equal(result.residual, false);
    assert.equal(result.deployed, 8);
    assert.deepEqual(
      env.gcp.deploys,
      FIXTURE_HANDLERS.map((h) => h.name),
    );
    for (const step of result.report.steps) {
      for (const [name, observed] of Object.entries(step.handlers)) {
        assert.equal(observed.matchesDocumented, true, `${step.id} ${name}`);
      }
    }
    assert.deepEqual(result.report.totals.unattributed, 0);
    // all back to the starting state
    assert.equal(env.gcp.functions.size, 0);
    assert.equal(env.gcp.triggers.size, 0);
    assert.equal(env.gcp.topics.size, 0);
    assert.equal(env.gcp.packages.size, 0);
    assert.equal(env.gcp.gcs.objects.size, 0, "the 2nd gen uploads are deleted by receipt");
    assert.equal(env.rtdbWorld.baseline(), true);
    assert.deepEqual(env.gcp.deleted.toSorted(), FIXTURE_HANDLERS.map((h) => h.name).toSorted());
    assert.equal(env.assembled.uploads.report().closureReady, true);
    // the forms of the debug lines: a 2nd gen receipt, a 1st gen external upload
    const forms = env.assembled.forms.summary();
    for (const h of FIXTURE_HANDLERS) {
      assert.equal(forms[h.name].receipt, h.generation === 2, h.name);
      assert.equal(forms[h.name].externalUpload, h.generation === 1, h.name);
      assert.deepEqual(forms[h.name].putStatusCodes, [200]);
    }
    assert.ok(env.assembled.forms.maskedLines().every((line) => !line.includes("SECRET-MARKER")));
  } finally {
    await finish(env);
  }
});

test("the requests of a clean run stay inside every ceiling", async () => {
  const env = await setup();
  try {
    await run(env);
    const used = env.budget.snapshot();
    const ceilings = { ...STAGE2_LIMITS, ...STAGE2_KINDS };
    for (const [kind, ceiling] of Object.entries(ceilings)) {
      assert.ok(used[kind] <= ceiling, `${kind}: ${used[kind]} of ${ceiling}`);
    }
    assert.equal(used.cliDeploy, 8);
    assert.equal(used.cliDelete, 0, "no function is deleted by a CLI selector");
    assert.equal(used.invocation, 0);
    assert.equal(used.auth, 0);
  } finally {
    await finish(env);
  }
});

test("a delivery production would not make shows up as such: a dropped event and a repeated one", async () => {
  const env = await setup({
    options: {
      dropEvents: new Set(["rtdbCreatedV2"]),
      duplicateEvents: new Set(["rtdbWrittenV1"]),
    },
  });
  try {
    const result = await run(env);
    // production is the oracle, but a delivery that did not come is read by a person before it is recorded
    assert.equal(result.outcome, "stopped-needs-review");
    assert.equal(result.residual, false, result.reasons.join("; "));
    assert.match(
      result.reasons.join(";"),
      /documented delivery received no frame: s1 rtdbCreatedV2/,
    );
    const s1 = result.report.steps.find((s) => s.id === "s1");
    assert.equal(s1.handlers.rtdbCreatedV2.frames, 0);
    assert.equal(s1.handlers.rtdbCreatedV2.matchesDocumented, false);
    assert.equal(s1.handlers.rtdbWrittenV1.frames, 2);
    assert.equal(s1.handlers.rtdbWrittenV1.distinctEventIds, 1);
    assert.equal(s1.handlers.rtdbWrittenV1.duplicateFrames, 1);
  } finally {
    await finish(env);
  }
});

test("a deploy that fails after creating its function: the function is deleted, nothing is written", async () => {
  const env = await setup({ options: { failDeploy: "rtdbCreatedV2" } });
  try {
    const result = await run(env);
    assert.equal(result.outcome, "stopped-needs-review");
    assert.equal(result.residual, false, result.reasons.join("; "));
    assert.equal(result.deployed, 4);
    assert.equal(env.gcp.functions.size, 0);
    assert.equal(env.gcp.deleted.length, 5);
    assert.equal(env.rtdbWorld.baseline(), true);
    assert.equal(Object.keys(env.rtdbWorld.tree).length, 0);
  } finally {
    await finish(env);
  }
});

test("an Eventarc trigger and topic left after the function delete are removed by their exact names", async () => {
  const env = await setup({ options: { leaveTrigger: true } });
  try {
    const result = await run(env);
    assert.equal(result.outcome, "recorded", result.reasons.join("; "));
    assert.equal(result.cleanup.inventory.deleted.length, 8, "four triggers and four topics");
    assert.equal(env.gcp.triggers.size, 0);
    assert.equal(env.gcp.topics.size, 0);
  } finally {
    await finish(env);
  }
});

test("a trigger the run did not make is never removed, and makes the run residual", async () => {
  const env = await setup({ options: { leaveTrigger: true } });
  try {
    env.gcp.triggers.add(`projects/${PROJECT}/locations/us-central1/triggers/stranger-1`);
    // it exists before the run, so it is in the baseline: no residue
    const clean = await run(env);
    assert.equal(clean.residual, false, clean.reasons.join("; "));
    assert.ok(
      env.gcp.triggers.has(`projects/${PROJECT}/locations/us-central1/triggers/stranger-1`),
    );
  } finally {
    await finish(env);
  }
});

test("a function with a name that collides stops the run before any RTDB request or deploy", async () => {
  const env = await setup({ options: { foreignFunctions: ["rtdbCreatedV2-extra"] } });
  try {
    const result = await run(env);
    assert.match(result.reasons.join(";"), /collides/);
    assert.equal(env.gcp.deploys.length, 0);
    assert.equal(env.rtdbWorld.sent.length, 0);
    assert.equal(result.residual, false);
  } finally {
    await finish(env);
  }
});

test("Cloud Logging that is not enabled stops the run at the preflight with nothing changed", async () => {
  const env = await setup({ options: { loggingState: "DISABLED" } });
  try {
    const result = await run(env);
    assert.match(result.reasons.join(";"), /Cloud Logging is not enabled/);
    assert.equal(env.gcp.deploys.length, 0);
    assert.equal(env.rtdbWorld.sent.length, 0);
  } finally {
    await finish(env);
  }
});

test("an unknown answer to a write ends the sequence, the write is not repeated, and the prefix delete clears the tree", async () => {
  const env = await setup({
    rtdbFaults: [{ method: "PATCH", path: /items\/a\.json$/u, kind: "timeout" }],
  });
  try {
    const result = await run(env);
    assert.equal(result.outcome, "stopped-needs-review");
    assert.match(result.reasons.join(";"), /write s2 answer is unknown/);
    assert.equal(env.rtdbWorld.sent.filter((s) => s.startsWith("PATCH")).length, 1);
    assert.equal(result.residual, false, result.reasons.join("; "));
    assert.equal(env.rtdbWorld.baseline(), true);
    assert.equal(env.gcp.functions.size, 0);
  } finally {
    await finish(env);
  }
});

test("a stop request after the second write ends the run quickly and cleans up", async () => {
  const abort = { stopped: false };
  const env = await setup({ abort });
  const original = env.assembled.deps.rtdb.write;
  env.assembled.deps.rtdb.write = async (step) => {
    const answer = await original(step);
    if (step.id === "s2") abort.stopped = true;
    return answer;
  };
  try {
    const result = await run(env);
    assert.match(result.reasons.join(";"), /signal/);
    assert.equal(result.residual, false, result.reasons.join("; "));
    assert.equal(env.gcp.functions.size, 0);
    assert.equal(env.rtdbWorld.baseline(), true);
    assert.equal(STEPS.length, 9);
  } finally {
    await finish(env);
  }
});

test("the upload ceiling is wired into the helper: a run short of requests stops before a deploy it could not account for", async () => {
  const env = await setup();
  try {
    // leave fewer than the fifteen requests one deploy reserves
    for (let n = 0; n < STAGE2_LIMITS.upload - 14; n += 1) env.budget.take("upload");
    const result = await run(env);
    assert.match(result.reasons.join(";"), /upload request budget is short/);
    assert.equal(env.gcp.deploys.length, 0);
    assert.equal(env.rtdbWorld.baseline(), true);
  } finally {
    await finish(env);
  }
});

test("the 1st gen upload bucket outside the project is never listed, read or deleted", async () => {
  const env = await setup();
  try {
    await run(env);
    const outside = "uploads-100000000001";
    assert.ok(env.gcp.requests.length > 100);
    assert.ok(env.gcp.requests.every((request) => !request.url.includes(outside)));
    assert.ok(env.gcp.gcs.requests.every((request) => !request.url.includes(outside)));
    // the deploy lines were seen (the form is recorded), only nothing was done about them
    assert.equal(env.assembled.forms.summary().rtdbCreatedV1.externalUpload, true);
  } finally {
    await finish(env);
  }
});

test("a stranger's write to the public item is not taken for the run's own: its frames stay unattributed and the run needs review", async () => {
  const env = await setup();
  const original = env.assembled.deps.rtdb.write;
  env.assembled.deps.rtdb.write = async (step) => {
    if (step.id === "s8") {
      // somebody else writes the same path with a value that has no nonce, just before the run does
      await env.rtdbWorld.fetch(`https://x.test/${PREFIX}/items/c.json`, {
        method: "PUT",
        body: JSON.stringify({ n: 1 }),
        headers: {},
      });
    }
    return original(step);
  };
  try {
    const result = await run(env);
    assert.equal(result.outcome, "stopped-needs-review");
    assert.match(result.reasons.join(";"), /could not be attributed to a write \(no-match: \d+\)/);
    assert.ok(result.report.totals.unattributed > 0);
    assert.equal(result.residual, false, result.reasons.join("; "));
    // the nonce is in every value of the run
    assert.match(result.nonce, /^[0-9a-f]{16}$/u);
  } finally {
    await finish(env);
  }
});
