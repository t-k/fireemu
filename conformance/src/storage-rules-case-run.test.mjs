import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { createRehearsalDeps } from "./storage-rules-s9/deps.mjs";
import { observe, readback } from "./storage-rules-s9/observe.mjs";
import { BUCKET, PROJECT, S9_PLAN } from "./storage-rules-s9/plan.mjs";
import { CASE_PLAN } from "./storage-rules-s9/plan-case.mjs";
import {
  PLANS,
  planFor,
  pins,
  productionOptions,
  readbackRun as realReadbackRun,
  recordProductionRun as realRecordProductionRun,
  tokenSource,
} from "./storage-rules-s9/run.mjs";

// A rehearsal: every collaborator is injected, so no flag is needed and nothing real is reachable.
const noNetwork = async () => {
  throw new Error("a rehearsal has no network");
};
const readbackRun = (options) => realReadbackRun({ rehearsal: true, net: noNetwork, ...options });
const recordProductionRun = (options) => realRecordProductionRun({ rehearsal: true, ...options });
import { createWorld } from "./storage-rules-s9/world.fake.mjs";
import { withProjectLocks } from "./storage-rules/project-locks.mjs";

const scratch = mkdtempSync(join(tmpdir(), "case-run-"));
after(() => rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
const fresh = () => join(scratch, `d${(counter += 1)}`);
const baselineName = `projects/${PROJECT}/rulesets/22b746af-0000-4000-8000-000000000001`;
const quiet = { log() {}, error() {} };

function execWith(tokens = []) {
  return (cmd, args) => {
    if (cmd === "git" && args.includes("rev-parse")) return `${"a".repeat(40)}\n`;
    if (cmd === "git") return "";
    if (cmd === "gcloud") {
      tokens.push("minted");
      return `ya29.token${tokens.length}\n`;
    }
    throw new Error(`unexpected ${cmd}`);
  };
}

describe("choosing the family", () => {
  it("knows exactly the s9 and case families, and refuses any other name", () => {
    assert.deepEqual(Object.keys(PLANS).toSorted(), ["case", "s9"]);
    assert.equal(planFor("case"), CASE_PLAN);
    assert.equal(planFor("s9"), S9_PLAN);
    for (const bad of ["", "S9", "cases", "__proto__", "constructor", undefined])
      assert.throws(() => planFor(bad), /unknown plan/);
  });

  it("requires --plan on a production command line, and passes the plan on", () => {
    const argv = ["--baseline", "absent", "--out", "d"];
    assert.throws(() => productionOptions(argv), /--plan is required/);
    assert.equal(productionOptions([...argv, "--plan", "case"]).plan, CASE_PLAN);
    assert.equal(productionOptions([...argv, "--plan", "s9"]).plan, S9_PLAN);
    assert.throws(() => productionOptions([...argv, "--plan", "x"]), /unknown plan/);
  });

  it("pins the modules the case family adds", () => {
    const pin = pins(execWith());
    for (const file of ["plan-case.mjs", "reading.mjs"])
      assert.match(pin.modules[file], /^[0-9a-f]{64}$/);
  });
});

describe("the run of the case family", () => {
  function setup(over = {}) {
    const plan = over.plan ?? CASE_PLAN;
    const seen = { locks: [], observer: [] };
    const options = {
      plan,
      baseline: baselineName,
      outPath: fresh(),
      env: { PATH: "/bin" },
      exec: execWith(),
      newId: () => "sr-0123abcd",
      pid: 4242,
      log: quiet,
      guardEgress() {},
      locks: async (lockOptions, use) => {
        seen.locks.push(lockOptions);
        await use({ confirmClosed() {} });
      },
      makeDeps: () => ({ fake: true }),
      observer: async (args) => {
        seen.observer.push(args);
        return { report: { runId: args.runId, closureReady: true, rows: [], loads: [] } };
      },
      ...over,
    };
    return { options, seen };
  }

  it("locks under its own task id, hands the plan to the observer and records it in the header", async () => {
    const { options, seen } = setup();
    const final = await recordProductionRun(options);
    assert.equal(seen.locks[0].taskId, "STORAGE-RULES-CASE");
    assert.equal(seen.observer[0].plan, CASE_PLAN);
    const header = JSON.parse(readFileSync(join(options.outPath, "run-header.json"), "utf8"));
    assert.equal(header.plan, "case");
    assert.equal(final.estimatedUsd, CASE_PLAN.estimatedUsd);
  });

  it("puts the reading of the rows into the case receipt and report, and nothing into the s9 one", async () => {
    const rows = [1, 2].flatMap((recording) =>
      CASE_PLAN.rows.map((row) => ({
        recording,
        id: row.id,
        class: row.candidates.full ? "allow" : "deny",
      })),
    );
    const lines = [];
    const { options } = setup({
      log: { log: (text) => lines.push(text), error() {} },
      observer: async (args) => ({
        report: { runId: args.runId, closureReady: true, rows, loads: [] },
      }),
    });
    const final = await recordProductionRun(options);
    assert.equal(final.reading.verdict, "full");
    assert.equal(final.reading.complete, true);
    assert.deepEqual(final.reading.mismatches.full, []);
    assert.ok(final.reading.mismatches.ascii.length > 0);
    assert.ok(final.reading.mismatches.simple.length > 0);
    assert.ok(!("table" in final.reading));
    assert.equal(JSON.parse(lines[0]).reading.verdict, "full");
    const saved = JSON.parse(readFileSync(join(options.outPath, "run-report.json"), "utf8"));
    assert.equal(saved.reading.verdict, "full");
    const s9 = setup({ plan: S9_PLAN });
    assert.equal("reading" in (await recordProductionRun(s9.options)), false);
  });

  it("reads a run with no rows as incomplete, not as a verdict", async () => {
    const { options } = setup();
    const final = await recordProductionRun(options);
    assert.equal(final.reading.verdict, "incomplete");
  });

  it("keeps the s9 task id for the s9 family", async () => {
    const { options, seen } = setup({ plan: S9_PLAN });
    await recordProductionRun(options);
    assert.equal(seen.locks[0].taskId, "STORAGE-RULES-S9");
    assert.equal(seen.observer[0].plan, S9_PLAN);
  });
});

describe("a token that outlives its hour (S9 review SF1)", () => {
  it("mints once, keeps the token for forty minutes, then mints a fresh one", () => {
    let now = 0;
    let minted = 0;
    const source = tokenSource({ mint: () => `t${(minted += 1)}`, now: () => now });
    assert.equal(source.get(), "t1");
    now = 39 * 60_000;
    assert.equal(source.get(), "t1");
    now = 40 * 60_000;
    assert.equal(source.get(), "t1", "exactly forty minutes old is still fresh");
    now = 40 * 60_000 + 1;
    assert.equal(source.get(), "t2");
    now += 10 * 60_000;
    assert.equal(source.get(), "t2");
    assert.equal(minted, 2);
  });

  it("keeps the old token when a fresh one cannot be minted, and tries again at the next use", () => {
    let now = 0;
    let fail = false;
    let minted = 0;
    const source = tokenSource({
      mint: () => {
        minted += 1;
        if (fail) throw new Error("gcloud");
        return "t1";
      },
      now: () => now,
    });
    assert.equal(source.get(), "t1");
    fail = true;
    now = 41 * 60_000;
    assert.equal(source.get(), "t1");
    assert.equal(source.get(), "t1");
    assert.equal(minted, 3);
  });

  it("sends a token minted after forty minutes to the cleanup of a long run", async () => {
    const dir = fresh();
    mkdirSync(dir);
    const tokens = [];
    let clock = Date.parse("2026-11-12T00:00:00Z");
    const fake = createWorld({
      plan: CASE_PLAN,
      project: PROJECT,
      bucket: BUCKET,
      baseline: baselineName,
      lag: 0,
    });
    const authorizations = [];
    const net = async (request) => {
      clock += 60_000; // every request takes a minute of the fake clock
      authorizations.push(request.headers.authorization);
      return fake.net(request);
    };
    await recordProductionRun({
      plan: CASE_PLAN,
      baseline: baselineName,
      outPath: join(dir, "out"),
      lockDir: join(dir, "locks"),
      legacyLock: join(dir, "legacy.lock"),
      exec: execWith(tokens),
      newId: () => "sr-0123abcd",
      pid: process.pid,
      log: quiet,
      guardEgress() {},
      clock: () => clock,
      makeDeps: ({ token, lease }) => ({
        ...createRehearsalDeps({ accessToken: "unused", token, lease, net }),
        sleep: async () => {},
      }),
    });
    const owner = authorizations.filter((a) => a !== undefined);
    assert.ok(tokens.length >= 3, `minted ${tokens.length} times`);
    assert.equal(owner[0], "Bearer ya29.token1");
    assert.notEqual(owner.at(-1), owner[0]);
    assert.equal(owner.at(-1), `Bearer ya29.token${tokens.length}`);
  });
});

describe("a read that fails in transport does not keep the lock (S9 review SF4)", () => {
  async function longRun({ failOn }) {
    const dir = fresh();
    mkdirSync(dir);
    const fake = createWorld({
      plan: CASE_PLAN,
      project: PROJECT,
      bucket: BUCKET,
      baseline: baselineName,
      lag: 0,
      faults: [{ match: failOn, answer: "transport" }],
    });
    const options = {
      plan: CASE_PLAN,
      baseline: baselineName,
      outPath: join(dir, "out"),
      lockDir: join(dir, "locks"),
      legacyLock: join(dir, "legacy.lock"),
      exec: execWith(),
      newId: () => "sr-0123abcd",
      pid: process.pid,
      log: quiet,
      guardEgress() {},
      makeDeps: ({ token, lease }) => ({
        ...createRehearsalDeps({ accessToken: "unused", token, lease, net: fake.net }),
        sleep: async () => {},
      }),
    };
    return { dir, options, fake };
  }
  const lockFiles = (dir) =>
    existsSync(join(dir, "locks")) ? readdirSync(join(dir, "locks")) : [];

  it("releases the lock after a run that only lost an anonymous row read", async () => {
    const { dir, options } = await longRun({
      failOn: (r) =>
        r.method === "GET" && r.path.includes("/v0/") && r.path.includes("ctl-upper-true"),
    });
    const final = await recordProductionRun(options);
    assert.equal(final.unknownReads, 1);
    assert.equal(final.closureReady, true);
    assert.deepEqual(lockFiles(dir), []);
  });

  it("keeps the lock after a run that lost the answer to a write", async () => {
    const { dir, options } = await longRun({
      failOn: (r) => r.method === "DELETE" && r.path.includes("/storage/v1/"),
    });
    await assert.rejects(recordProductionRun(options), /outbound attempt failed|cannot confirm/);
    assert.equal(lockFiles(dir).length, 1);
  });
});

describe("the A2 read-back does not close what the run left open (S9 review SF3)", () => {
  const target = { name: "production", bucket: BUCKET, project: PROJECT, rehearsal: true };
  const runId = "sr-0123abcd";
  const owner = { authorization: "Bearer t", "x-goog-user-project": PROJECT };
  const entry = [
    {
      name: `projects/${PROJECT}/rulesets/22b746af-0000-4000-8000-000000000001`,
      services: ["firebase.storage"],
    },
    {
      name: `projects/${PROJECT}/rulesets/d0abf7c6-0000-4000-8000-000000000002`,
      services: ["cloud.firestore"],
    },
  ];
  const memory = () => {
    const saved = {};
    return { saved, journal() {}, save: (n, d) => (saved[n] = d) };
  };
  const read = (unknowns) => {
    const fake = createWorld({
      plan: CASE_PLAN,
      project: PROJECT,
      bucket: BUCKET,
      baseline: baselineName,
      lag: 0,
    });
    return readback({
      plan: CASE_PLAN,
      target,
      runId,
      baseline: baselineName,
      entry,
      unknowns,
      deps: { net: fake.net, adminHeaders: () => owner },
      out: memory(),
    });
  };

  it("closes when the run had no unknown answer, or only unknown reads and deletes", async () => {
    assert.equal((await read([])).closed, true);
    assert.equal((await read(["row/1/ctl-upper-true"])).closed, true);
    assert.equal((await read(["rec1/restore/delete"])).closed, true);
  });

  it("stays open, naming the label, for an unknown create of an object, a ruleset or a load", async () => {
    for (const label of [
      "create/ctl-upper-true",
      "rec1/case/ruleset",
      "rec2/load/s7-lone-surrogate",
    ]) {
      const report = await read([label]);
      assert.equal(report.closed, false, label);
      assert.deepEqual(report.openCreates, [label]);
      assert.ok(report.problems.some((p) => /unknown create/.test(p)));
    }
  });

  it("stays open when the run's own report cannot be read", async () => {
    const report = await read(null);
    assert.equal(report.closed, false);
    assert.ok(report.problems.some((p) => /run report/.test(p)));
  });

  it("reads the run report from the run directory, and passes null for a missing or broken one", async () => {
    const dir = fresh();
    const out = join(dir);
    const { newOutDir } = await import("./storage-rules-s9/run.mjs");
    const o = newOutDir(out);
    o.save("run-header.json", { runId, baseline: baselineName, plan: "case" });
    o.save("entry.json", { baseline: baselineName, entryRulesets: entry });
    const seen = [];
    const common = {
      dir,
      exec: execWith(),
      guardEgress() {},
      now: () => new Date("2026-11-12T00:00:00.000Z"),
      reader: async (args) => {
        seen.push(args);
        return { closed: true };
      },
      log: quiet,
    };
    await readbackRun(common);
    assert.equal(seen[0].unknowns, null, "no report: unknown state");
    assert.equal(seen[0].plan, CASE_PLAN);
    writeFileSync(join(dir, "run-report.json"), "{broken");
    await readbackRun({ ...common, now: () => new Date("2026-11-12T00:00:01.000Z") });
    assert.equal(seen[1].unknowns, null);
    writeFileSync(join(dir, "run-report.json"), JSON.stringify({ unknowns: ["create/x"] }));
    await readbackRun({ ...common, now: () => new Date("2026-11-12T00:00:02.000Z") });
    assert.deepEqual(seen[2].unknowns, ["create/x"]);
    writeFileSync(join(dir, "run-report.json"), JSON.stringify({ requests: 1 }));
    await readbackRun({ ...common, now: () => new Date("2026-11-12T00:00:03.000Z") });
    assert.equal(seen[3].unknowns, null, "a report without an unknowns list is not a report");
  });

  it("reads a header without a plan as the s9 family, as the first run wrote it", async () => {
    const dir = fresh();
    const { newOutDir } = await import("./storage-rules-s9/run.mjs");
    const o = newOutDir(dir);
    o.save("run-header.json", { runId, baseline: baselineName });
    o.save("entry.json", { baseline: baselineName, entryRulesets: entry });
    let plan;
    await readbackRun({
      dir,
      exec: execWith(),
      guardEgress() {},
      now: () => new Date("2026-11-12T00:00:00.000Z"),
      reader: async (args) => ((plan = args.plan), { closed: true }),
      log: quiet,
    });
    assert.equal(plan, S9_PLAN);
  });
});

// Referenced so a bundler of the tests keeps the import: the glue above builds on both modules.
void [observe, withProjectLocks];
