import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { observe } from "./storage-rules-s9/observe.mjs";
import { BUCKET, PROJECT } from "./storage-rules-s9/plan.mjs";
import { CASE_PLAN } from "./storage-rules-s9/plan-case.mjs";
import { newOutDir, ownRulesetsOf, recoverRun } from "./storage-rules-s9/run.mjs";
import { createWorld } from "./storage-rules-s9/world.fake.mjs";

const scratch = mkdtempSync(join(tmpdir(), "case-recover-"));
after(() => rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
const fresh = () => join(scratch, `d${(counter += 1)}`);
const runId = "sr-0123abcd";
const baselineName = `projects/${PROJECT}/rulesets/22b746af-0000-4000-8000-000000000001`;
const target = { name: "production", bucket: BUCKET, project: PROJECT };
const owner = { authorization: "Bearer t", "x-goog-user-project": PROJECT };
const memory = () => {
  const saved = {};
  return { saved, journal() {}, save: (n, d) => (saved[n] = d) };
};
const quiet = { log() {}, error() {} };
const gitExec = (cmd, args) => {
  if (cmd === "gcloud") return "ya29.t\n";
  return args.includes("rev-parse") ? `${"a".repeat(40)}\n` : "";
};
const json = (v) => Buffer.from(JSON.stringify(v));
const rulesApi = `https://firebaserules.googleapis.com/v1/projects/${PROJECT}`;
const releaseUrl = `${rulesApi}/releases/firebase.storage/${BUCKET}`;

/** A world as a run that died mid-recording leaves it: the release on its ruleset, objects under its prefix. */
async function deadRun({ baseline = baselineName, objects = 3 } = {}) {
  const fake = createWorld({
    plan: CASE_PLAN,
    project: PROJECT,
    bucket: BUCKET,
    baseline: baseline === "absent" ? null : baseline,
    lag: 0,
  });
  const send = (method, url, headers, body) => fake.net({ method, url, headers, body });
  const listing = await send("GET", `${rulesApi}/rulesets?pageSize=100`, owner);
  const entryRulesets = JSON.parse(listing.body.toString()).rulesets.map((r) => ({
    name: r.name,
    services: r.metadata.services,
  }));
  const made = await send(
    "POST",
    `${rulesApi}/rulesets`,
    owner,
    json({
      source: {
        files: [
          {
            name: "storage.rules",
            content: CASE_PLAN.programs[0].source(CASE_PLAN.recordingPrefix(runId, 1)),
          },
        ],
      },
    }),
  );
  const rulesetName = JSON.parse(made.body.toString()).name;
  if (baseline === "absent")
    await send(
      "POST",
      `${rulesApi}/releases`,
      owner,
      json({ name: `projects/${PROJECT}/releases/firebase.storage/${BUCKET}`, rulesetName }),
    );
  else
    await send(
      "PATCH",
      releaseUrl,
      owner,
      json({
        release: { name: `projects/${PROJECT}/releases/firebase.storage/${BUCKET}`, rulesetName },
        updateMask: "rulesetName",
      }),
    );
  const P = CASE_PLAN.recordingPrefix(runId, 1);
  for (const id of Object.keys(CASE_PLAN.objects).slice(0, objects))
    await send(
      "POST",
      `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(BUCKET)}/o?uploadType=media&name=${encodeURIComponent(CASE_PLAN.objectName(id, P))}&ifGenerationMatch=0`,
      owner,
      Buffer.from("x"),
    );
  return { fake, entryRulesets, rulesetName };
}

async function recover(fake, { baseline = baselineName, entryRulesets, ownRulesets }) {
  const out = memory();
  const { report } = await observe({
    plan: CASE_PLAN,
    target,
    runId,
    baseline,
    deps: { net: fake.net, adminHeaders: () => owner, sleep: async () => {} },
    out,
    recover: { entryRulesets, ownRulesets },
  });
  return { report, out };
}

describe("recovering a run that stopped (S9 review SF5)", () => {
  it("puts the release back, deletes the run's ruleset and objects, and closes", async () => {
    const { fake, entryRulesets, rulesetName } = await deadRun();
    assert.equal(fake.world.release.rulesetName, rulesetName);
    const { report } = await recover(fake, { entryRulesets, ownRulesets: [rulesetName] });
    assert.equal(report.mode, "recover");
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.deepEqual(fake.world.release, { rulesetName: baselineName });
    assert.equal(fake.world.objects.size, 0);
    assert.ok(!fake.world.rulesets.has(rulesetName));
    assert.ok(fake.world.rulesets.has(baselineName), "the baseline ruleset is not the run's");
    assert.ok(report.requests <= CASE_PLAN.staticBounds(2).cleanup + 20);
  });

  it("deletes the release when the bucket had none, and nothing else of the baseline", async () => {
    const { fake, entryRulesets, rulesetName } = await deadRun({ baseline: "absent" });
    const { report } = await recover(fake, {
      baseline: "absent",
      entryRulesets,
      ownRulesets: [rulesetName],
    });
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    assert.equal(fake.world.release, null);
    assert.equal(fake.world.rulesets.size, 2);
  });

  it("writes nothing to a release that already is the baseline, and reads first", async () => {
    const { fake, entryRulesets, rulesetName } = await deadRun();
    await fake.net({
      method: "PATCH",
      url: releaseUrl,
      headers: owner,
      body: json({
        release: {
          name: `projects/${PROJECT}/releases/firebase.storage/${BUCKET}`,
          rulesetName: baselineName,
        },
        updateMask: "rulesetName",
      }),
    });
    const before = fake.world.calls.length;
    const { report } = await recover(fake, { entryRulesets, ownRulesets: [rulesetName] });
    assert.equal(report.closureReady, true, JSON.stringify(report.problems));
    const mine = fake.world.calls.slice(before);
    assert.ok(mine.every((c) => !(c.method === "PATCH" && c.url.includes("/releases/"))));
    assert.equal(mine[0].method, "GET");
    assert.ok(mine[0].url.includes("/releases/firebase.storage/"));
  });

  it("refuses to delete a ruleset it was not told is the run's", async () => {
    const { fake, entryRulesets } = await deadRun();
    const { report } = await recover(fake, { entryRulesets, ownRulesets: [] });
    assert.ok(fake.world.rulesets.size >= 3, "the run's ruleset stays when it is not named");
    assert.equal(report.closureReady, false, "the ruleset list differs from the entry list");
    assert.ok(report.problems.some((p) => /ruleset list/.test(p)));
  });

  it("does not delete an object that is not one of the run's planned names", async () => {
    const { fake, entryRulesets, rulesetName } = await deadRun();
    const stray = `${CASE_PLAN.runRoot(runId)}rec1/stray`;
    await fake.net({
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(BUCKET)}/o?uploadType=media&name=${encodeURIComponent(stray)}&ifGenerationMatch=0`,
      headers: owner,
      body: Buffer.from("x"),
    });
    const { report } = await recover(fake, { entryRulesets, ownRulesets: [rulesetName] });
    assert.ok(fake.world.objects.has(stray));
    assert.equal(report.closureReady, false);
  });

  it("never re-sends a delete whose answer is unknown, and does not close", async () => {
    const { fake, entryRulesets, rulesetName } = await deadRun({ baseline: "absent" });
    fake.world.faults.push({
      match: (r) => r.method === "DELETE" && r.path.includes("/releases/"),
      answer: "transport",
    });
    const { report } = await recover(fake, {
      baseline: "absent",
      entryRulesets,
      ownRulesets: [rulesetName],
    });
    const deletes = fake.world.calls.filter(
      (c) => c.method === "DELETE" && c.url.includes("/releases/"),
    );
    assert.equal(deletes.length, 1);
    assert.equal(report.closureReady, false);
    assert.ok(report.unknowns.length > 0);
  });
});

describe("the recover command", () => {
  const sourceRun = () => {
    const dir = fresh();
    const o = newOutDir(dir);
    o.save("run-header.json", { runId, baseline: baselineName, plan: "case" });
    return { dir, o };
  };

  it("reads the run's own ruleset names from its journal: created and answered 200 only", () => {
    const lines = [
      { phase: "before", n: 1, kind: "ruleset-create" },
      {
        phase: "after",
        n: 1,
        status: 200,
        bodyBase64: json({ name: `projects/${PROJECT}/rulesets/aaa111` }).toString("base64"),
      },
      { phase: "before", n: 2, kind: "ruleset-create" },
      {
        phase: "after",
        n: 2,
        status: 400,
        bodyBase64: json({ name: `projects/${PROJECT}/rulesets/bad` }).toString("base64"),
      },
      { phase: "before", n: 3, kind: "ruleset-create" },
      { phase: "unknown", n: 3, reason: "transport" },
      { phase: "before", n: 4, kind: "ruleset-list" },
      {
        phase: "after",
        n: 4,
        status: 200,
        bodyBase64: json({ name: `projects/${PROJECT}/rulesets/listed` }).toString("base64"),
      },
      { phase: "before", n: 5, kind: "ruleset-create" },
      {
        phase: "after",
        n: 5,
        status: 200,
        bodyBase64: json({ name: "projects/other/rulesets/zzz" }).toString("base64"),
      },
      { phase: "after", n: 6, status: 200, bodyBase64: "not json" },
    ].map((l) => JSON.stringify(l));
    assert.deepEqual(ownRulesetsOf(lines.join("\n"), PROJECT), [
      `projects/${PROJECT}/rulesets/aaa111`,
    ]);
    assert.deepEqual(ownRulesetsOf("", PROJECT), []);
  });

  it("takes the project lock under the plan's task id, recovers into a new directory and closes the lock only for a closed recovery", async () => {
    const { dir, o } = sourceRun();
    o.save("entry.json", {
      baseline: baselineName,
      entryRulesets: [{ name: "n", services: ["s"] }],
    });
    writeFileSync(
      join(dir, "journal.jsonl"),
      `${JSON.stringify({ phase: "before", n: 1, kind: "ruleset-create" })}\n${JSON.stringify({ phase: "after", n: 1, status: 200, bodyBase64: json({ name: `projects/${PROJECT}/rulesets/aaa111` }).toString("base64") })}\n`,
    );
    const seen = { locks: [], observer: [], closed: 0 };
    const final = await recoverRun({
      dir,
      exec: gitExec,
      env: {},
      guardEgress() {},
      pid: 7,
      now: () => new Date("2026-11-12T00:00:00.000Z"),
      locks: async (opts, use) => {
        seen.locks.push(opts);
        await use({ confirmClosed: () => (seen.closed += 1) });
      },
      makeDeps: () => ({ fake: true }),
      observer: async (args) => {
        seen.observer.push(args);
        return { report: { runId, mode: "recover", closureReady: true, rows: [], loads: [] } };
      },
      log: quiet,
    });
    assert.equal(seen.locks[0].taskId, "STORAGE-RULES-CASE");
    assert.equal(seen.locks[0].packetId, `${runId}-recover`);
    assert.deepEqual(seen.locks[0].projects, [PROJECT]);
    assert.equal(seen.observer[0].plan, CASE_PLAN);
    assert.deepEqual(seen.observer[0].recover, {
      entryRulesets: [{ name: "n", services: ["s"] }],
      ownRulesets: [`projects/${PROJECT}/rulesets/aaa111`],
    });
    assert.equal(seen.observer[0].baseline, baselineName);
    assert.equal(seen.closed, 1);
    assert.equal(final.closureReady, true);
    const made = readdirSync(dir).filter((f) => f.startsWith("recover-"));
    assert.equal(made.length, 1);
    assert.ok(readdirSync(join(dir, made[0])).includes("run-report.json"));
    const header = JSON.parse(readFileSync(join(dir, made[0], "run-header.json"), "utf8"));
    assert.equal(header.recoverOf, runId);
    assert.equal(seen.locks[0].acquiredAt, "2026-11-12T00:00:00Z");
  });

  it("keeps the lock when the recovery did not close, and refuses without an entry list or with ambient credentials", async () => {
    const { dir, o } = sourceRun();
    const common = {
      dir,
      exec: gitExec,
      env: {},
      guardEgress() {},
      pid: 7,
      locks: async (opts, use) => use({ confirmClosed: () => assert.fail("must not close") }),
      makeDeps: () => ({}),
      observer: async () => ({ report: { runId, closureReady: false, rows: [], loads: [] } }),
      log: quiet,
    };
    await assert.rejects(
      recoverRun({ ...common, now: () => new Date("2026-11-12T00:00:00.000Z") }),
      /entry\.json/,
    );
    o.save("entry.json", { baseline: baselineName, entryRulesets: [] });
    await assert.rejects(
      recoverRun({
        ...common,
        env: { FIREBASE_TOKEN: "x" },
        now: () => new Date("2026-11-12T00:00:01.000Z"),
      }),
      /refusing to start with FIREBASE_TOKEN/,
    );
    const final = await recoverRun({ ...common, now: () => new Date("2026-11-12T00:00:02.000Z") });
    assert.equal(final.closureReady, false);
  });
});
