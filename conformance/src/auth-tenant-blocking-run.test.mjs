import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  otherLaneOnSandbox,
  recentAbort,
  restoreDue,
  restoreSandbox,
  TASK_ID,
} from "./auth-tenant-blocking/run.mjs";

async function admitLocal(rows, suite = "tenant") {
  const dir = await mkdtemp(join(tmpdir(), "atb-admission-"));
  try {
    const ledger = join(dir, "ledger.jsonl");
    await writeFile(
      ledger,
      rows.map((row) => (typeof row === "string" ? row : JSON.stringify(row))).join("\n") + "\n",
    );
    return spawnSync(
      process.execPath,
      [join(import.meta.dirname, "auth-tenant-blocking/run.mjs"), "admit-local"],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          AUTH_TENANT_SUITE: suite,
          FIREEMU_SANDBOX_LEDGER: ledger,
          FIREEMU_AUTH_SANDBOX_WEB_CONFIG: "",
          FIREEMU_AUTH_TENANT_PRIVATE_DIR: "",
        },
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("local admission accepts a clean ledger without credentials for both suites", async () => {
  for (const suite of ["tenant", "blocking"]) {
    const result = await admitLocal([], suite);
    assert.equal(result.status, 0, `${suite}: ${result.stderr}`);
  }
});

test("local admission refuses own hold and recent abort before IAM", async () => {
  const now = Date.now();
  const row = (age, fields) => ({
    ts: new Date(now - age).toISOString(),
    project: "fireemu-oracle-idp",
    taskId: "AUTH-TENANT-SANDBOX",
    ...fields,
  });
  for (const rows of [
    [row(2 * 3_600_000, { event: "started" })],
    [row(59 * 60_000, { outcome: "aborted-fatal", estimatedUsd: 0 })],
  ]) {
    const result = await admitLocal(rows);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /last run/);
  }
  assert.equal(
    (await admitLocal([row(61 * 60_000, { outcome: "aborted-fatal", estimatedUsd: 0 })])).status,
    0,
  );
});

test("local admission refuses another lane's open or recent task including IAM hold", async () => {
  const now = Date.now();
  const row = (age, taskId, fields) => ({
    ts: new Date(now - age).toISOString(),
    project: "fireemu-oracle-idp",
    taskId,
    ...fields,
  });
  for (const rows of [
    [row(2 * 3_600_000, "AUTH-MFA-SANDBOX", { event: "started" })],
    [row(29 * 60_000, "AUTH-MFA-SANDBOX", { outcome: "recorded", estimatedUsd: 0 })],
    [row(2 * 3_600_000, "AUTH-TENANT-SANDBOX-IAM", { event: "started" })],
  ]) {
    const result = await admitLocal(rows);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /another lane/);
  }
  assert.equal(
    (
      await admitLocal([
        row(31 * 60_000, "AUTH-MFA-SANDBOX", { outcome: "recorded", estimatedUsd: 0 }),
      ])
    ).status,
    0,
  );
});

test("local admission fails closed on malformed rows and unknown task cost", async () => {
  const now = new Date(Date.now() - 2 * 3_600_000).toISOString();
  for (const rows of [
    ["{broken-json"],
    ['"oops"'],
    ["[]"],
    ["null"],
    [{ ts: now, project: "fireemu-oracle-idp", taskId: "AUTH-MFA-SANDBOX" }],
    [{ ts: now, project: "fireemu-oracle-idp", event: "started" }],
    [
      {
        ts: "not-a-date",
        project: "fireemu-oracle-idp",
        taskId: "AUTH-MFA-SANDBOX",
        event: "note",
      },
    ],
    [{ ts: now, project: "", taskId: "AUTH-MFA-SANDBOX", event: "note" }],
    [
      {
        ts: now,
        project: "fireemu-oracle-idp",
        taskId: "AUTH-TENANT-SANDBOX",
        outcome: "recorded",
      },
    ],
  ]) {
    const result = await admitLocal(rows);
    assert.notEqual(result.status, 0);
  }
});

test("local admission accepts the historical taskless terminal", async () => {
  const result = await admitLocal([
    {
      ts: "2026-09-23T15:02:54+00:00",
      project: "fireemu-oracle-idp",
      outcome: "exploratory-not-evidence",
      requests: 17,
      estimatedUsd: 0,
    },
  ]);
  assert.equal(result.status, 0, result.stderr);
});

test("local admission reserves the reviewed run cost within each task's US$10 budget", async () => {
  const ts = new Date(Date.now() - 2 * 3_600_000).toISOString();
  for (const [suite, prior, accepted] of [
    ["tenant", 9, true],
    ["tenant", 9.01, false],
    ["blocking", 5, true],
    ["blocking", 5.01, false],
  ]) {
    const taskId = suite === "tenant" ? "AUTH-TENANT-SANDBOX" : "AUTH-BLOCKING-SANDBOX";
    const result = await admitLocal(
      [{ ts, project: "fireemu-oracle-idp", taskId, outcome: "recorded", estimatedUsd: prior }],
      suite,
    );
    assert.equal(result.status === 0, accepted, `${suite} prior=${prior}: ${result.stderr}`);
  }
});

test("an unfinished run of this suite blocks another recording at any age", () => {
  const now = Date.now();
  const ledger = [
    {
      ts: new Date(now - 3 * 3_600_000).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: TASK_ID,
      outcome: "recorded",
    },
    {
      ts: new Date(now - 2 * 3_600_000).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: TASK_ID,
      event: "started",
    },
  ]
    .map((row) => JSON.stringify(row))
    .join("\n");
  assert.equal(recentAbort(ledger, now)?.event, "started");
  const closed = `${ledger}\n${JSON.stringify({ ts: new Date(now).toISOString(), project: "fireemu-oracle-idp", taskId: TASK_ID, outcome: "recorded" })}\n`;
  assert.equal(recentAbort(closed, now), undefined);
});

test("another suite's hold and thirty-minute gap both block admission", () => {
  const now = Date.now();
  const other = TASK_ID === "AUTH-TENANT-SANDBOX" ? "AUTH-BLOCKING-SANDBOX" : "AUTH-TENANT-SANDBOX";
  const row = (age, fields) =>
    `${JSON.stringify({ ts: new Date(now - age).toISOString(), project: "fireemu-oracle-idp", taskId: other, ...fields })}\n`;
  assert.match(
    otherLaneOnSandbox(row(2 * 3_600_000, { event: "started" }), now),
    /has not finished/,
  );
  assert.match(otherLaneOnSandbox(row(20 * 60_000, { outcome: "recorded" }), now), /wrote a line/);
  assert.equal(otherLaneOnSandbox(row(31 * 60_000, { outcome: "recorded" }), now), undefined);
});

test("a note after another lane's start does not close its hold", () => {
  const now = Date.now();
  const other = "AUTH-MFA-SANDBOX";
  const row = (age, fields) =>
    JSON.stringify({
      ts: new Date(now - age).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: other,
      ...fields,
    });
  const ledger = `${row(3 * 3_600_000, { event: "started" })}\n${row(2 * 3_600_000, { event: "note" })}\n`;
  assert.match(otherLaneOnSandbox(ledger, now), /has not finished/);
  const closed = `${ledger}${row(31 * 60_000, { event: "finished", outcome: "recorded" })}\n`;
  assert.equal(otherLaneOnSandbox(closed, now), undefined);
});

test("a failed restore cannot close another lane's old hold", () => {
  const now = Date.now();
  const row = (age, fields) =>
    JSON.stringify({
      ts: new Date(now - age).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: "AUTH-MFA-SANDBOX",
      ...fields,
    });
  const started = `${row(3 * 3_600_000, { event: "started" })}\n`;
  const failed = `${started}${row(2 * 3_600_000, { event: "finished", outcome: "restore-failed", sandboxAtBaseline: false })}\n`;
  assert.match(otherLaneOnSandbox(failed, now), /has not finished|not confirmed clean/);
  const restored = `${failed}${row(31 * 60_000, { event: "finished", outcome: "restored-by-operator", sandboxAtBaseline: true })}\n`;
  assert.equal(otherLaneOnSandbox(restored, now), undefined);
  const unverified = `${failed}${row(31 * 60_000, { event: "finished", outcome: "restored-by-operator", sandboxAtBaseline: false })}\n`;
  assert.match(otherLaneOnSandbox(unverified, now), /has not finished|not confirmed clean/);
});

test("a verified cleanup event closes a foreign failed run's hold", () => {
  const now = Date.now();
  const row = (age, fields) =>
    JSON.stringify({
      ts: new Date(now - age).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: "FS-RULES-SANDBOX",
      ...fields,
    });
  const ledger = `${row(3 * 3_600_000, { event: "started" })}\n${row(2 * 3_600_000, { outcome: "aborted-cleanup-incomplete" })}\n${row(31 * 60_000, { event: "cleanup-verified" })}\n`;
  assert.equal(otherLaneOnSandbox(ledger, now), undefined);
});

test("failed restore after this task's start keeps its own hold", () => {
  const now = Date.now();
  const row = (age, fields) =>
    JSON.stringify({
      ts: new Date(now - age).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: TASK_ID,
      ...fields,
    });
  const ledger = `${row(3 * 3_600_000, { event: "started" })}\n${row(2 * 3_600_000, { event: "finished", outcome: "restore-failed", sandboxAtBaseline: false })}\n`;
  assert.equal(recentAbort(ledger, now)?.event, "started");
});

test("an IAM campaign hold survives sandbox restoration and blocks new recordings", async () => {
  const now = Date.now();
  const project = "fireemu-oracle-idp";
  const iamTask = `${TASK_ID}-IAM`;
  const row = (taskId, fields) =>
    JSON.stringify({ ts: new Date(now).toISOString(), project, taskId, ...fields });
  const iamOnly = `${row(iamTask, { event: "started", reason: "IAM binding uncertain" })}\n`;
  assert.equal(restoreDue(iamOnly), false);
  assert.match(otherLaneOnSandbox(iamOnly, now + 2 * 3_600_000), /has not finished/);

  const dir = await mkdtemp(join(tmpdir(), "atb-iam-hold-"));
  const ledger = join(dir, "ledger.jsonl");
  try {
    await writeFile(ledger, `${row(TASK_ID, { event: "started" })}\n${iamOnly}`, { mode: 0o600 });
    const foreignIamTask = `${TASK_ID === "AUTH-TENANT-SANDBOX" ? "AUTH-BLOCKING-SANDBOX" : "AUTH-TENANT-SANDBOX"}-IAM`;
    await writeFile(
      ledger,
      `${row(TASK_ID, { event: "started" })}\n${row(foreignIamTask, { event: "started" })}\n`,
    );
    await assert.rejects(
      restoreSandbox({ ledger, isRecordingRunning: async () => false }),
      /another lane is on the sandbox/,
    );
    await writeFile(ledger, `${row(TASK_ID, { event: "started" })}\n${iamOnly}`);
    await assert.rejects(
      restoreSandbox({
        ledger,
        isRecordingRunning: async () => false,
        webConfig: async () => ({ projectNumber: "123456789012" }),
        context: async () => {
          throw new Error("sandbox recovery reached its context");
        },
      }),
      /sandbox recovery reached its context/,
    );
    const afterFailure = await readFile(ledger, "utf8");
    assert.match(otherLaneOnSandbox(afterFailure, now + 2 * 3_600_000), /has not finished/);
    await restoreSandbox({
      ledger,
      isRecordingRunning: async () => false,
      webConfig: async () => ({ projectNumber: "123456789012" }),
      context: async () => ({}),
      sessionFactory: () => ({
        readConfig: async () => ({}),
        writeConfig: async () => {},
        listTenants: async () => [],
        counts: () => ({ harnessRequests: 0 }),
      }),
      baselineCheck: async () => {},
    });
    const afterSandboxSuccess = await readFile(ledger, "utf8");
    assert.equal(
      afterSandboxSuccess.trim().split("\n").map(JSON.parse).at(-1).outcome,
      "restored-by-hand",
    );
    assert.match(otherLaneOnSandbox(afterSandboxSuccess, now + 2 * 3_600_000), /has not finished/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an early restore failure retains the sandbox hold for every later preflight", async () => {
  for (const phase of ["production context", "session construction"]) {
    const dir = await mkdtemp(join(tmpdir(), "atb-restore-ledger-"));
    const ledger = join(dir, "ledger.jsonl");
    try {
      await writeFile(
        ledger,
        `${JSON.stringify({ ts: new Date(Date.now() - 2 * 3_600_000).toISOString(), event: "started", taskId: TASK_ID, project: "fireemu-oracle-idp" })}\n`,
        { mode: 0o600 },
      );
      await assert.rejects(
        restoreSandbox({
          ledger,
          isRecordingRunning: async () => false,
          webConfig: async () => ({ projectNumber: "123456789012" }),
          context: async () => {
            if (phase === "production context") throw new Error("context unavailable");
            return {};
          },
          sessionFactory: () => {
            throw new Error("session unavailable");
          },
        }),
        phase === "production context" ? /context unavailable/ : /session unavailable/,
      );
      const text = await readFile(ledger, "utf8");
      const rows = text.trim().split("\n").map(JSON.parse);
      assert.equal(rows.at(-2).outcome, "restore-failed", phase);
      assert.equal(rows.at(-1).event, "started", phase);
      assert.equal(restoreDue(text), true, phase);
      assert.equal(recentAbort(text, Date.now() + 2 * 3_600_000)?.event, "started", phase);
      const foreignView = text.replaceAll(TASK_ID, "ANOTHER-SANDBOX-TASK");
      assert.match(
        otherLaneOnSandbox(foreignView, Date.now() + 2 * 3_600_000),
        /has not finished/,
        phase,
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
});
