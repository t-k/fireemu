import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, it } from "node:test";

import { createProductionDeps, fetchNet } from "./storage-rules-s9/deps.mjs";
import { observe, readback } from "./storage-rules-s9/observe.mjs";
import { BUCKET, ESTIMATED_USD, PROJECT, S9_PLAN } from "./storage-rules-s9/plan.mjs";
import {
  adcToken,
  argValue,
  finish,
  gitState,
  newOutDir,
  pins,
  productionOptions,
  readbackRun as realReadbackRun,
  recordProductionRun as realRecordProductionRun,
} from "./storage-rules-s9/run.mjs";

// A rehearsal: every collaborator is injected, so no flag is needed and nothing real is reachable.
const noNetwork = async () => {
  throw new Error("a rehearsal has no network");
};
const readbackRun = (options) => realReadbackRun({ rehearsal: true, net: noNetwork, ...options });
const recordProductionRun = (options) => realRecordProductionRun({ rehearsal: true, ...options });
import { createWorld } from "./storage-rules-s9/world.fake.mjs";

const scratch = mkdtempSync(join(tmpdir(), "s9-run-"));
after(() => rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
const fresh = () => join(scratch, `d${(counter += 1)}`);
const baselineName = `projects/${PROJECT}/rulesets/22b746af-0000-4000-8000-000000000001`;
const sink = () => {
  const lines = [];
  const errors = [];
  return { lines, errors, log: (text) => lines.push(text), error: (text) => errors.push(text) };
};
const cleanExec =
  (calls = []) =>
  (cmd, args, options) => {
    calls.push([cmd, args, options]);
    if (cmd === "git" && args.includes("rev-parse")) return `${"a".repeat(40)}\n`;
    if (cmd === "git") return "";
    if (cmd === "gcloud") return "ya29.token\n";
    throw new Error(`unexpected ${cmd}`);
  };

describe("storage rules s9 output directory and receipts", () => {
  it("creates a private directory, appends journal lines and writes private JSON files", () => {
    const path = fresh();
    const out = newOutDir(path);
    assert.equal(out.path, path);
    assert.equal(statSync(path).mode & 0o777, 0o700);
    out.journal({ phase: "a", n: 1 });
    out.journal({ phase: "b", n: 2 });
    out.save("x.json", { a: [1] });
    const lines = readFileSync(join(path, "journal.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.deepEqual([lines[0].phase, lines[0].n, lines[1].phase], ["a", 1, "b"]);
    assert.match(lines[0].ts, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.equal(readFileSync(join(path, "x.json"), "utf8"), '{\n  "a": [\n    1\n  ]\n}\n');
    assert.equal(statSync(join(path, "x.json")).mode & 0o777, 0o600);
    assert.equal(statSync(join(path, "journal.jsonl")).mode & 0o777, 0o600);
    out.save("x.json", { a: 2 });
    assert.deepEqual(JSON.parse(readFileSync(join(path, "x.json"), "utf8")), { a: 2 });
    assert.throws(() => newOutDir(path), /EEXIST/, "a run directory is never reused");
    assert.throws(() => newOutDir(join(path, "a", "b")), /ENOENT/, "no parents are made");
  });

  it("prints the receipt without rows and loads, then saves the full report", () => {
    const path = fresh();
    const out = newOutDir(path);
    const logger = sink();
    const full = finish(
      out,
      { runId: "r", rows: [1], loads: [2], closureReady: true },
      { startedAt: "s" },
      { log: logger.log, error: logger.error },
    );
    const printed = JSON.parse(logger.lines[0]);
    assert.equal(printed.runId, "r");
    assert.equal(printed.startedAt, "s");
    assert.equal(printed.estimatedUsd, ESTIMATED_USD);
    assert.ok(!("rows" in printed) && !("loads" in printed));
    assert.match(printed.finishedAt, /^\d{4}-\d\d-\d\dT/);
    const saved = JSON.parse(readFileSync(join(path, "run-report.json"), "utf8"));
    assert.deepEqual(saved.rows, [1]);
    assert.deepEqual(saved.loads, [2]);
    assert.deepEqual(full, saved);
    const broken = finish(
      {
        save() {
          throw new Error("disk full");
        },
      },
      { runId: "r" },
      {},
      { log: logger.log, error: logger.error },
    );
    assert.equal(broken.runId, "r");
    assert.deepEqual(logger.errors, ["run-report.json not saved: disk full"]);
  });
});

describe("storage rules s9 pins and credentials", () => {
  it("reads the git state of this checkout, and null when git cannot be run", () => {
    const calls = [];
    const state = gitState(cleanExec(calls));
    assert.deepEqual(state, { gitSha: "a".repeat(40), dirty: false });
    assert.deepEqual(
      calls.map((c) => c[1].slice(2)),
      [
        ["rev-parse", "HEAD"],
        ["status", "--porcelain"],
      ],
    );
    for (const call of calls) assert.equal(call[2].encoding, "utf8");
    const dirty = gitState((cmd, args) => (args.includes("rev-parse") ? "b\n" : " M file\n"));
    assert.deepEqual(dirty, { gitSha: "b", dirty: true });
    assert.deepEqual(
      gitState(() => {
        throw new Error("no git");
      }),
      { gitSha: null, dirty: null },
    );
  });

  it("pins every module of the recorder by its digest", () => {
    const pin = pins(cleanExec());
    assert.equal(pin.gitSha, "a".repeat(40));
    assert.equal(pin.dirty, false);
    assert.deepEqual(Object.keys(pin.modules), [
      "plan.mjs",
      "plan-case.mjs",
      "reading.mjs",
      "guard.mjs",
      "judge.mjs",
      "wire.mjs",
      "observe.mjs",
      "deps.mjs",
      "run.mjs",
    ]);
    for (const digest of Object.values(pin.modules)) assert.match(digest, /^[0-9a-f]{64}$/);
    assert.equal(pin.node, process.version);
  });

  it("asks gcloud for the application default token once, with a timeout and no stdin", () => {
    const calls = [];
    assert.equal(adcToken(cleanExec(calls)), "ya29.token");
    assert.equal(calls.length, 1);
    assert.equal(calls[0][0], "gcloud");
    assert.deepEqual(calls[0][1], ["auth", "application-default", "print-access-token"]);
    assert.deepEqual(calls[0][2], {
      encoding: "utf8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.throws(
      () =>
        adcToken(() => {
          throw new Error("secret detail");
        }),
      (error) => error.message === "ADC token acquisition failed",
    );
  });
});

describe("storage rules s9 production run glue", () => {
  const target = { name: "production", bucket: BUCKET, project: PROJECT, rehearsal: true };
  function setup(over = {}) {
    const calls = { guard: [], locks: [], deps: [], observer: [], closed: 0, order: [] };
    const logger = sink();
    const lease = { confirmClosed: () => (calls.closed += 1) };
    const options = {
      baseline: baselineName,
      outPath: fresh(),
      env: { PATH: "/bin" },
      exec: cleanExec(calls.order),
      newId: () => "sr-0123abcd",
      pid: 4242,
      log: { log: logger.log, error: logger.error },
      guardEgress: (hosts) => {
        calls.order.push(["guard"]);
        calls.guard.push(hosts);
      },
      locks: async (lockOptions, use) => {
        calls.order.push(["locks"]);
        calls.locks.push(lockOptions);
        await use(lease);
      },
      makeDeps: (args) => {
        calls.deps.push(args);
        return { fake: true };
      },
      observer: async (args) => {
        calls.observer.push(args);
        return { report: { runId: args.runId, closureReady: true, rows: [], loads: [] } };
      },
      ...over,
    };
    return { options, calls, logger, lease };
  }

  it("takes the project lock, observes with the token and closes the lock only for a closed run", async () => {
    const { options, calls, logger } = setup();
    const final = await recordProductionRun(options);
    assert.equal(calls.guard.length, 1);
    assert.deepEqual(calls.guard[0], [
      "storage.googleapis.com",
      "firebasestorage.googleapis.com",
      "firebaserules.googleapis.com",
    ]);
    assert.equal(calls.locks.length, 1);
    const lock = calls.locks[0];
    assert.deepEqual(Object.keys(lock).sort(), [
      "acquiredAt",
      "legacyLockPath",
      "lockDir",
      "packetId",
      "pid",
      "projects",
      "sourceCommit",
      "taskId",
    ]);
    assert.deepEqual(lock.projects, [PROJECT]);
    assert.equal(lock.taskId, "STORAGE-RULES-S9");
    assert.equal(lock.packetId, "sr-0123abcd");
    assert.equal(lock.sourceCommit, "a".repeat(40));
    assert.equal(lock.pid, 4242);
    assert.match(lock.acquiredAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.equal(lock.lockDir, "docs.local/runs/sandbox-locks");
    assert.equal(lock.legacyLockPath, "docs.local/runs/sandbox-ledger.jsonl.lock");
    assert.deepEqual(calls.deps[0].accessToken, "ya29.token");
    assert.ok(calls.deps[0].lease);
    const seen = calls.observer[0];
    assert.deepEqual(seen.target, target);
    assert.equal(seen.runId, "sr-0123abcd");
    assert.equal(seen.baseline, baselineName);
    assert.deepEqual(seen.deps, { fake: true });
    assert.equal(calls.closed, 1);
    assert.equal(final.closureReady, true);
    assert.equal(final.gitSha, "a".repeat(40), "the final report carries the pins");
    assert.deepEqual(Object.keys(final.modules).length, 9);
    assert.match(final.startedAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.equal(final.estimatedUsd, ESTIMATED_USD);
    assert.equal(JSON.parse(logger.lines[0]).runId, "sr-0123abcd");
    const header = JSON.parse(readFileSync(join(options.outPath, "run-header.json"), "utf8"));
    assert.equal(header.runId, "sr-0123abcd");
    assert.equal(header.baseline, baselineName);
    assert.equal(header.gitSha, "a".repeat(40));
    assert.deepEqual(header.target, target);
    assert.equal(
      header.startedAt,
      lock.acquiredAt.replace("Z", `.${header.startedAt.slice(20, 23)}Z`),
    );
    assert.deepEqual(readdirSync(options.outPath).sort(), ["run-header.json", "run-report.json"]);
    // The guard goes up before the credential is read, and the lock is taken after both.
    const names = calls.order.map((c) => c[0]);
    assert.ok(names.indexOf("guard") < names.indexOf("gcloud"));
    assert.ok(names.indexOf("gcloud") < names.indexOf("locks"));
  });

  it("keeps the lock when the run is not closed, and passes the lock paths it is given", async () => {
    const open = setup({
      lockDir: "/x/locks",
      legacyLock: "/x/legacy.lock",
      observer: async () => ({ report: { runId: "r", closureReady: false, rows: [], loads: [] } }),
    });
    await recordProductionRun(open.options);
    assert.equal(open.calls.closed, 0);
    assert.equal(open.calls.locks[0].lockDir, "/x/locks");
    assert.equal(open.calls.locks[0].legacyLockPath, "/x/legacy.lock");
  });

  it("refuses before any side effect: ambient credentials, a bad baseline, a dirty or unknown checkout", async () => {
    for (const name of [
      "GOOGLE_APPLICATION_CREDENTIALS",
      "FIREBASE_TOKEN",
      "CLOUDSDK_CORE_PROJECT",
    ]) {
      const { options, calls } = setup({ env: { [name]: "x" } });
      await assert.rejects(
        recordProductionRun(options),
        new RegExp(`refusing to start with ${name} set`),
      );
      assert.equal(calls.order.length, 0);
      assert.equal(calls.locks.length, 0);
    }
    const bad = setup({ baseline: "present" });
    await assert.rejects(recordProductionRun(bad.options), /baseline is neither/);
    assert.equal(bad.calls.order.length, 0);
    const dirty = setup({ exec: (cmd, args) => (args.includes("rev-parse") ? "a\\n" : " M x\\n") });
    await assert.rejects(recordProductionRun(dirty.options), /uncommitted or untracked/);
    assert.equal(dirty.calls.guard.length, 0);
    const unknown = setup({
      exec: () => {
        throw new Error("no git");
      },
    });
    await assert.rejects(recordProductionRun(unknown.options), /git state is unavailable/);
    const token = setup({
      exec: (cmd, args) =>
        cmd === "gcloud"
          ? (() => {
              throw new Error("x");
            })()
          : cleanExec()(cmd, args),
    });
    await assert.rejects(recordProductionRun(token.options), /ADC token acquisition failed/);
    assert.equal(token.calls.locks.length, 0);
  });

  it("does not reuse an output directory", async () => {
    const used = fresh();
    newOutDir(used);
    const { options, calls } = setup({ outPath: used });
    await assert.rejects(recordProductionRun(options), /EEXIST/);
    assert.equal(calls.guard.length, 0);
  });
});

describe("storage rules s9 read-back glue", () => {
  it("reads the run's own header and entry list and writes new time-stamped files", async () => {
    const dir = fresh();
    const out = newOutDir(dir);
    out.save("run-header.json", { runId: "sr-0123abcd", baseline: baselineName });
    out.save("entry.json", {
      baseline: baselineName,
      entryRulesets: [{ name: "n", services: ["s"] }],
    });
    const seen = [];
    const logger = sink();
    const report = await readbackRun({
      dir,
      exec: cleanExec(),
      guardEgress: (hosts) => seen.push(["guard", hosts]),
      net: async () => ({ status: 200, headers: {}, body: Buffer.alloc(0) }),
      now: () => new Date("2026-11-08T15:30:45.123Z"),
      reader: async (args) => {
        seen.push(["reader", args]);
        args.out.journal({ phase: "x" });
        args.out.save("readback.json", { closed: true });
        return { closed: true };
      },
      log: { log: logger.log, error: logger.error },
    });
    assert.deepEqual(report, { closed: true });
    assert.deepEqual(seen[0], [
      "guard",
      ["storage.googleapis.com", "firebasestorage.googleapis.com", "firebaserules.googleapis.com"],
    ]);
    const args = seen[1][1];
    assert.equal(args.runId, "sr-0123abcd");
    assert.equal(args.baseline, baselineName);
    assert.deepEqual(args.entry, [{ name: "n", services: ["s"] }]);
    assert.deepEqual(args.target, {
      name: "production",
      bucket: BUCKET,
      project: PROJECT,
      rehearsal: true,
    });
    assert.deepEqual(args.deps.adminHeaders(), {
      authorization: "Bearer ya29.token",
      "x-goog-user-project": PROJECT,
    });
    const files = readdirSync(dir).sort();
    assert.ok(files.includes("readback-2026-11-08T153045123Z.json"), files.join());
    assert.ok(files.includes("readback-journal-2026-11-08T153045123Z.jsonl"), files.join());
    assert.equal(JSON.parse(logger.lines[0]).closed, true);
    // A second read-back at the same instant never overwrites the first one.
    await assert.rejects(
      readbackRun({
        dir,
        exec: cleanExec(),
        guardEgress() {},
        now: () => new Date("2026-11-08T15:30:45.123Z"),
        reader: async (a) => a.out.save("readback.json", {}),
        log: { log() {}, error() {} },
      }),
      /EEXIST/,
    );
  });
});

describe("storage rules s9 network edges", () => {
  async function server(handler) {
    const s = http.createServer(handler);
    await new Promise((resolve) => s.listen(0, "127.0.0.1", resolve));
    return { s, url: `http://127.0.0.1:${s.address().port}` };
  }

  it("sends a request body only when there is one", async () => {
    const seen = [];
    const { s, url } = await server((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        seen.push({
          method: req.method,
          body: Buffer.concat(chunks).toString(),
          type: req.headers["content-type"],
        });
        res.end();
      });
    });
    try {
      await fetchNet({
        method: "POST",
        url,
        headers: { "content-type": "text/plain" },
        body: Buffer.from("abc"),
      });
      await fetchNet({ method: "GET", url, headers: {} });
      assert.deepEqual(seen, [
        { method: "POST", body: "abc", type: "text/plain" },
        { method: "GET", body: "", type: undefined },
      ]);
    } finally {
      s.close();
    }
  });

  it("verifies the lock before every production request, and sends nothing when it is lost", async () => {
    const steps = [];
    const lost = createProductionDeps({
      accessToken: "t",
      lease: {
        verifyHeld: async () => {
          steps.push("verify");
          throw new Error("lock lost");
        },
        dispatch: async () => steps.push("dispatch"),
      },
    });
    await assert.rejects(
      lost.net({ method: "GET", url: "http://127.0.0.1:1/x", headers: {} }),
      /lock lost/,
    );
    assert.deepEqual(steps, ["verify"]);
    assert.equal(typeof lost.now(), "number");
    await lost.sleep(1);
  });
});

describe("storage rules s9 read-back of a finished run", () => {
  const target = { name: "production", bucket: BUCKET, project: PROJECT, rehearsal: true };
  const runId = "sr-0123abcd";
  const owner = { authorization: "Bearer t", "x-goog-user-project": PROJECT };
  const sinks = () => {
    const saved = {};
    const journal = [];
    return {
      saved,
      journal,
      out: { journal: (e) => journal.push(e), save: (n, d) => (saved[n] = d) },
    };
  };
  async function finished(baseline = baselineName) {
    const fake = createWorld({
      project: PROJECT,
      bucket: BUCKET,
      baseline: baseline === "absent" ? null : baseline,
      lag: 0,
    });
    const first = sinks();
    await observe({
      target,
      runId,
      baseline,
      deps: { net: fake.net, adminHeaders: () => owner, sleep: async () => {} },
      out: first.out,
    });
    return { fake, entry: first.saved["entry.json"].entryRulesets };
  }
  const read = async (fake, entry, baseline = baselineName, over = {}) => {
    const s = sinks();
    const report = await readback({
      target,
      runId,
      baseline,
      entry,
      deps: { net: over.net ?? fake.net, adminHeaders: () => owner },
      out: s.out,
      ...over.options,
    });
    return { report, ...s };
  };

  it("closes after a clean run with 58 reads, and saves the report", async () => {
    const { fake, entry } = await finished();
    const { report, saved, journal } = await read(fake, entry);
    assert.deepEqual(report, {
      runId,
      requests: 58,
      unknownReads: 0,
      openCreates: [],
      problems: [],
      closed: true,
    });
    assert.deepEqual(saved["readback.json"], report);
    const labels = [
      ...new Set(journal.filter((e) => e.phase === "before").map((e) => e.label)),
    ].sort();
    assert.deepEqual(labels, [
      "readback/list",
      "readback/object",
      "readback/release",
      "readback/rulesets",
    ]);
    const absent = await finished("absent");
    assert.equal((await read(absent.fake, absent.entry, "absent")).report.closed, true);
    assert.equal(
      (await read(absent.fake, absent.entry, baselineName)).report.problems[0],
      "the bucket release is not the baseline",
    );
    const present = await finished();
    assert.ok(
      (await read(present.fake, present.entry, "absent")).report.problems.includes(
        "the bucket release is not the baseline",
      ),
    );
  });

  it("names each thing that is still there", async () => {
    const { fake, entry } = await finished();
    const wrap = (match, answer) => ({ net: async (req) => (match(req) ? answer : fake.net(req)) });
    const json = (status, body) => ({
      status,
      headers: {},
      body: Buffer.from(JSON.stringify(body)),
    });
    const unreadableRelease = await read(
      fake,
      entry,
      baselineName,
      wrap((r) => r.url.includes("/releases/") && r.method === "GET", json(500, {})),
    );
    assert.ok(unreadableRelease.report.problems.includes("the bucket release is not the baseline"));
    assert.equal(unreadableRelease.report.unknownReads, 1);
    assert.equal(unreadableRelease.report.closed, false);
    const otherList = await read(
      fake,
      entry,
      baselineName,
      wrap((r) => r.url.includes("/rulesets?"), json(200, { rulesets: [] })),
    );
    assert.deepEqual(otherList.report.problems, ["the ruleset list is not the list at entry"]);
    const rootFull = json(200, {
      kind: "storage#objects",
      items: [{ name: "x", generation: "5" }],
    });
    const slash = await read(
      fake,
      entry,
      baselineName,
      wrap((r) => r.url.includes("o?prefix=%2Fstorage"), rootFull),
    );
    assert.deepEqual(slash.report.problems, ["the run root is not empty"]);
    const plain = await read(
      fake,
      entry,
      baselineName,
      wrap((r) => r.url.includes("o?prefix=storage"), rootFull),
    );
    assert.deepEqual(plain.report.problems, ["the run root is not empty"]);
    const unreadableList = await read(
      fake,
      entry,
      baselineName,
      wrap((r) => r.url.includes("o?prefix=storage"), json(503, {})),
    );
    assert.deepEqual(unreadableList.report.problems, ["the run root is not empty"]);
    const objectGone = await read(
      fake,
      entry,
      baselineName,
      wrap((r) => r.url.includes("/o/storage-rules-s9"), json(200, {})),
    );
    assert.deepEqual(objectGone.report.problems, ["an object still reads"]);
    assert.equal(objectGone.report.closed, false);
    const objectLost = await read(
      fake,
      entry,
      baselineName,
      wrap(
        (r) => r.url.includes("/o/storage-rules-s9%2Fsr-0123abcd%2Frec1%2Fmk%2Fa"),
        json(503, {}),
      ),
    );
    assert.deepEqual(objectLost.report.problems, ["an object still reads"]);
    assert.equal(objectLost.report.unknownReads, 1);
  });

  it("reads at most seventy things unless told otherwise", async () => {
    const { fake, entry } = await finished();
    // Three recordings of names would take 85 reads.
    await assert.rejects(
      read(fake, entry, baselineName, { options: { recordings: 3 } }),
      /request budget exhausted/,
    );
    const before = fake.world.calls.length;
    await assert.rejects(
      readback({
        target,
        runId,
        baseline: baselineName,
        entry,
        deps: { net: fake.net, adminHeaders: () => owner },
        out: sinks().out,
        recordings: 3,
      }),
    );
    assert.equal(fake.world.calls.length - before, 70);
  });

  it("reads an unreadable ruleset list as a list that differs", async () => {
    const { fake, entry } = await finished();
    const unreadable = await read(fake, entry, baselineName, {
      net: async (req) =>
        req.url.includes("/rulesets?")
          ? { status: 503, headers: {}, body: Buffer.from("{}") }
          : fake.net(req),
    });
    assert.deepEqual(unreadable.report.problems, ["the ruleset list is not the list at entry"]);
    assert.equal(unreadable.report.unknownReads, 1);
  });

  it("stops at its cap of reads", async () => {
    const { fake, entry } = await finished();
    await assert.rejects(
      read(fake, entry, baselineName, { options: { cap: 57 } }),
      /request budget exhausted/,
    );
    assert.equal(
      (await read(fake, entry, baselineName, { options: { cap: 58 } })).report.requests,
      58,
    );
    assert.equal(
      (await read(fake, entry, baselineName, { options: { cap: 58, recordings: 1 } })).report
        .requests,
      31,
    );
  });
});

describe("storage rules s9 command line options", () => {
  it("reads a named option, and nothing when it is missing or last", () => {
    assert.equal(argValue("out", ["node", "run.mjs", "x", "--out", "dir"]), "dir");
    assert.equal(argValue("out", ["--other", "dir"]), undefined);
    assert.equal(argValue("out", ["--out"]), undefined);
  });

  it("builds the production options, naming the lock paths only when they are given", () => {
    assert.deepEqual(productionOptions(["--plan", "s9", "--baseline", "absent", "--out", "d"]), {
      plan: S9_PLAN,
      baseline: "absent",
      outPath: "d",
    });
    assert.deepEqual(
      productionOptions([
        "--plan",
        "s9",
        "--out",
        "d",
        "--baseline",
        "absent",
        "--lock-dir",
        "/l",
        "--legacy-lock",
        "/g",
      ]),
      { plan: S9_PLAN, baseline: "absent", outPath: "d", lockDir: "/l", legacyLock: "/g" },
    );
    assert.deepEqual(
      productionOptions(["--plan", "s9", "--out", "d", "--baseline", "absent", "--lock-dir", "/l"]),
      { plan: S9_PLAN, baseline: "absent", outPath: "d", lockDir: "/l" },
    );
    assert.deepEqual(
      productionOptions([
        "--plan",
        "s9",
        "--out",
        "d",
        "--baseline",
        "absent",
        "--legacy-lock",
        "/g",
      ]),
      { plan: S9_PLAN, baseline: "absent", outPath: "d", legacyLock: "/g" },
    );
    assert.throws(
      () => productionOptions(["--plan", "s9", "--out", "d"]),
      /--baseline is required/,
    );
    assert.throws(
      () => productionOptions(["--plan", "s9", "--baseline", "absent"]),
      /--out is required/,
    );
  });

  it("runs git on this checkout with -C", () => {
    const calls = [];
    gitState(cleanExec(calls));
    for (const call of calls) {
      assert.equal(call[1][0], "-C");
      assert.match(call[1][1], /conformance\/src\/storage-rules-s9$/);
    }
  });
});

describe("storage rules s9 run receipts and read-back files", () => {
  it("carries the start time and the pins in the final report, and in the printed receipt", async () => {
    const logger = sink();
    const out = newOutDir(fresh());
    const full = finish(
      out,
      { runId: "r" },
      { startedAt: "2026-11-08T00:00:00.000Z", gitSha: "g" },
      { log: logger.log, error: logger.error },
    );
    assert.equal(full.startedAt, "2026-11-08T00:00:00.000Z");
    assert.equal(full.gitSha, "g");
    assert.equal(JSON.parse(logger.lines[0]).gitSha, "g");
  });

  it("writes the read-back journal and report as private, formatted files", async () => {
    const dir = fresh();
    const seeded = newOutDir(dir);
    seeded.save("run-header.json", { runId: "sr-0123abcd", baseline: "absent" });
    seeded.save("entry.json", { baseline: "absent", entryRulesets: [] });
    await readbackRun({
      dir,
      exec: cleanExec(),
      guardEgress() {},
      now: () => new Date("2026-11-08T15:30:45.123Z"),
      reader: async ({ out }) => {
        out.journal({ phase: "x", n: 1 });
        out.save("readback.json", { a: 1 });
        return {};
      },
      log: { log() {}, error() {} },
    });
    const journal = join(dir, "readback-journal-2026-11-08T153045123Z.jsonl");
    const report = join(dir, "readback-2026-11-08T153045123Z.json");
    const line = JSON.parse(readFileSync(journal, "utf8").trim());
    assert.deepEqual([line.phase, line.n], ["x", 1]);
    assert.match(line.ts, /^\d{4}-\d\d-\d\dT/);
    assert.equal(readFileSync(report, "utf8"), '{\n  "a": 1\n}\n');
    assert.equal(statSync(journal).mode & 0o777, 0o600);
    assert.equal(statSync(report).mode & 0o777, 0o600);
  });
});
