import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { access, chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { measure, planKind } from "./calendar-measure.mjs";
import { calendarFixture } from "./calendar-local.mjs";
import { readRecords } from "./calendar-recorder.mjs";
import { refusalVerdict, validateRecords } from "./calendar-accounting.mjs";

// End-to-end runs of harness H against a stand-in daemon (testdata/fake-fireemu.py), offline.
// The pinned build is never run here.
const here = (name) => fileURLToPath(new URL("./" + name, import.meta.url));
const portctl =
  process.env.FIREEMU_TEST_PORTCTL ??
  join(process.env.HOME ?? "/", ".agents/skills/port-registry/scripts/portctl.py");
const sourceRepo = fileURLToPath(new URL("../..", import.meta.url)).replace(/\/$/, "");
// The pinned build's source (stage3), whose format strings explain the refusal line.
const PINNED_SOURCE = "33970bf501ac85e62fd8aee488d16a9405a8a019";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const anchor = "2026-10-02T00:00:00Z";
const REFUSAL_ZONE = "Invalid/CalendarZone";
const refusalLine = `error: manifest: function "calendarProbe": time zone: unknown time zone "${REFUSAL_ZONE}"`;
const available = await access(portctl).then(
  () => true,
  () => false,
);
const skip = available ? false : "portctl.py is not installed";

async function fakeRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "calendar-measure-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const modules = join(root, "conformance/node_modules");
  await mkdir(join(modules, "firebase-functions/v2"), { recursive: true });
  await mkdir(join(modules, "firebase-tools"), { recursive: true });
  await writeFile(
    join(modules, "firebase-functions/package.json"),
    JSON.stringify({ name: "firebase-functions", version: "7.3.2" }),
  );
  await writeFile(
    join(modules, "firebase-tools/package.json"),
    JSON.stringify({ name: "firebase-tools", version: "15.28.2" }),
  );
  await writeFile(
    join(modules, "firebase-functions/v2/scheduler.js"),
    'exports.onSchedule = (options, handler) => ({ __endpoint: { kind: "schedule", ...options }, run: handler });\n',
  );
  await writeFile(
    join(modules, "firebase-functions/v2/https.js"),
    'exports.onRequest = (handler) => ({ __endpoint: { kind: "https" }, run: () => new Promise((resolve) => handler({}, { json: resolve })) });\n',
  );
  const binary = join(root, "fireemu");
  await writeFile(
    binary,
    `#!/bin/sh\nexec /usr/bin/python3 '${here("testdata/fake-fireemu.py")}' '${process.execPath}' "$@"\n`,
  );
  await chmod(binary, 0o755);
  return { root, binary, runner: here("testdata/fake-runner.cjs") };
}

async function planFor(t, { timeZone, control, positive }) {
  const { root, binary, runner } = await fakeRoot(t);
  const input = { schedule: "every 5 minutes", timeZone, scheduleTime: "2026-10-02T00:05:00Z" };
  const plan = {
    session: {
      root,
      binary,
      runner,
      binarySha256: digest(await readFile(binary)),
      runnerSha256: digest(await readFile(runner)),
      sourceCommit: PINNED_SOURCE,
      anchor,
      input,
    },
    portctl,
    sourceRepo,
    pins: {
      sourceCommit: PINNED_SOURCE,
      binarySha256: digest(await readFile(binary)),
      runnerSha256: digest(await readFile(runner)),
      fixtureSha256: digest(calendarFixture(input)),
      configSha256: digest(
        JSON.stringify({ schemaVersion: 1, profile: "strict", daemon: { clockStart: anchor } }),
      ),
      portctlSha256: digest(await readFile(portctl)),
      exitCode: 1,
      refusalLine,
    },
    ...(control ? { control } : {}),
    ...(positive ? { positive: true } : {}),
  };
  const path = join(root, "plan.json");
  await writeFile(path, JSON.stringify(plan));
  return { path, plan };
}

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

test("a plan names one run kind, and each control runs on its own fixture variant", () => {
  const session = (timeZone) => ({ session: { input: { timeZone } } });
  assert.deepEqual(planKind(session(REFUSAL_ZONE)), {
    kind: "certificate",
    escalation: "on",
    certificate: true,
  });
  assert.throws(() => planKind(session("Asia/Tokyo")), /refusal fixture/);
  assert.equal(planKind({ ...session("Asia/Tokyo"), positive: true }).escalation, "on");
  assert.throws(() => planKind({ ...session(REFUSAL_ZONE), positive: true }));
  assert.deepEqual(planKind({ ...session(REFUSAL_ZONE), control: { mode: "orphan" } }), {
    kind: "control",
    escalation: "off",
    certificate: false,
  });
  assert.throws(() => planKind({ ...session("Asia/Tokyo"), control: { mode: "orphan" } }));
  assert.throws(() => planKind({ ...session(REFUSAL_ZONE), control: { mode: "escaper" } }));
  assert.equal(
    planKind({ ...session("Asia/Tokyo"), control: { mode: "leftover" } }).escalation,
    "on",
  );
  assert.throws(() => planKind({ ...session(REFUSAL_ZONE), control: { mode: "toString" } }));
  assert.throws(() =>
    planKind({ ...session(REFUSAL_ZONE), control: { mode: "orphan" }, positive: true }),
  );
});

test(
  "a certificate whose pinned line the pinned source does not explain is never launched",
  { skip },
  async (t) => {
    const { path, plan } = await planFor(t, { timeZone: REFUSAL_ZONE });
    for (const line of [
      refusalLine.replace("error: ", "fatal: "),
      refusalLine + ".",
      'error: functions[default]: manifest: function "calendarProbe": time zone: unknown time zone "Invalid/CalendarZone"',
    ]) {
      await writeFile(path, JSON.stringify({ ...plan, pins: { ...plan.pins, refusalLine: line } }));
      await assert.rejects(measure(path), /not explained by the pinned source/, line);
    }
    await writeFile(
      path,
      JSON.stringify({ ...plan, pins: { ...plan.pins, sourceCommit: "a".repeat(40) } }),
    );
    await assert.rejects(measure(path), /not explained by the pinned source/);
    const runs = join(plan.session.root, "conformance/.runs");
    for (const name of await readdir(runs)) {
      const records = await readRecords(join(runs, name, "records/measure.jsonl"));
      assert.ok(!records.some((row) => row.type === "birth" && row.purpose === "outer"), name);
    }
  },
);

test(
  "the refusal run passes (A)-(G) end to end against the stand-in daemon",
  { skip },
  async (t) => {
    const { path } = await planFor(t, { timeZone: REFUSAL_ZONE });
    const report = await measure(path);
    for (const [letter, condition] of Object.entries(report.verdict.conditions))
      assert.equal(condition.outcome, "pass", `${letter}: ${condition.reasons}`);
    assert.equal(report.verdict.verdict, "pass");
    assert.equal(report.control, null);
    assert.equal(report.chain.outerSid, report.chain.outerPid);
    assert.notEqual(report.chain.rootSid, report.chain.outerSid);
    assert.deepEqual(report.claims, []);
    assert.equal(report.lsofByPid, "skipped: no recorded identity alive");
    assert.ok(Array.isArray(report.selfEnded.inner) && Array.isArray(report.selfEnded.outer));
  },
);

test(
  "the positive control passes (B)-(F) and observes the runner and the child; (v) a removed record file fails (C)",
  { skip },
  async (t) => {
    const { path, plan } = await planFor(t, { timeZone: "Asia/Tokyo", positive: true });
    const report = await measure(path);
    assert.equal(report.control.counts, true, JSON.stringify(report.verdict.conditions));
    assert.equal(report.verdict.conditions.A.outcome, "fail", "exit 0 is not the pinned refusal");
    // Control (v): the same run's records with one lane-owned file removed.
    const records = join(report.accountingDirectory, "records");
    const files = {};
    for (const name of ["measure.jsonl", "outer.jsonl"])
      files[name] = await readRecords(join(records, name));
    const validated = validateRecords(files);
    assert.equal(validated.ok, false);
    const judged = refusalVerdict({ ...plan, records: validated });
    assert.equal(judged.conditions.C.outcome, "fail");
  },
);

for (const [mode, timeZone, rule] of [
  ["orphan", REFUSAL_ZONE, "session"],
  ["escaper", "Asia/Tokyo", "identity"],
  ["listener", REFUSAL_ZONE, "port"],
  ["leftover", "Asia/Tokyo", "harness-signal"],
])
  test(
    `the ${mode} control fires its named rule (${rule}) on the injected helper`,
    { skip, timeout: 240000 },
    async (t) => {
      const { path } = await planFor(t, { timeZone, control: { mode, hold: 150 } });
      const report = await measure(path);
      t.after(() => {
        if (report.control?.injected?.pid && alive(report.control.injected.pid))
          process.kill(report.control.injected.pid, "SIGKILL");
      });
      assert.equal(report.verdict.verdict, "fail", "a control is never a pass");
      assert.ok(report.control.rulesFired.includes(rule), JSON.stringify(report.control));
      assert.equal(report.control.counts, true);
      assert.ok(
        report.control.injected.firstSighting,
        "the helper's first sighting is recorded (F2)",
      );
      const post = await readRecords(join(report.accountingDirectory, "post-verdict.jsonl"));
      // The leftover is the one helper the harness has already removed before the verdict.
      if (mode !== "leftover")
        assert.ok(
          post.some(
            (row) => row.type === "signal" && row.target.pid === report.control.injected.pid,
          ),
          "post-verdict cleanup signalled the helper by its identity",
        );
      // A killed orphan stays a zombie until launchd reaps it.
      for (let i = 0; i < 40 && alive(report.control.injected.pid); i++)
        await new Promise((resolve) => setTimeout(resolve, 50));
      assert.equal(alive(report.control.injected.pid), false, "post-verdict cleanup stopped it");
    },
  );
