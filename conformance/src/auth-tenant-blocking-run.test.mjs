import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  assertReviewedLock,
  productionStartedRow,
  otherLaneOnSandbox,
  recentAbort,
  restoreDue,
  restoreSandbox,
  TASK_ID,
} from "./auth-tenant-blocking/run.mjs";

async function admitLocal(rows, suite = "tenant", budget = "1800") {
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
          FIREEMU_AUTH_TENANT_REQUEST_BUDGET: budget,
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

test("local admission refuses a campaign without a request budget that carries it", async () => {
  for (const budget of ["", "2001", "300"]) {
    const result = await admitLocal([], "tenant", budget);
    assert.notEqual(result.status, 0, budget);
    assert.match(result.stderr, /request budget|REQUEST_BUDGET/, budget);
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

test("local admission accepts an older control observation without closing a foreign run", async () => {
  const now = Date.now();
  const row = (age, event) => ({
    ts: new Date(now - age).toISOString(),
    project: "fireemu-oracle-idp",
    taskId: "FS-RULES-SANDBOX",
    event,
  });
  const oldControl = row(31 * 60_000, "control");
  const accepted = await admitLocal([oldControl]);
  assert.equal(accepted.status, 0, accepted.stderr);

  const held = await admitLocal([row(2 * 3_600_000, "started"), oldControl]);
  assert.notEqual(held.status, 0);
  assert.match(held.stderr, /another lane.*has not finished/);
});

test("local admission fails closed on malformed rows and unknown task cost", async () => {
  const now = new Date(Date.now() - 2 * 3_600_000).toISOString();
  for (const rows of [
    ["{broken-json"],
    ['"oops"'],
    ["[]"],
    ["null"],
    [{ ts: now, project: "fireemu-oracle-idp", taskId: "AUTH-MFA-SANDBOX" }],
    [{ ts: now, project: "fireemu-oracle-idp", taskId: "AUTH-MFA-SANDBOX", event: "finished" }],
    [{ ts: now, project: "fireemu-oracle-idp", event: "started" }],
    [
      {
        ts: "2026-09-23T15:02:54+00:00",
        project: "fireemu-oracle-idp",
        outcome: "exploratory-not-evidence",
        taskId: null,
      },
    ],
    [
      {
        ts: "not-a-date",
        project: "fireemu-oracle-idp",
        taskId: "AUTH-MFA-SANDBOX",
        event: "note",
      },
    ],
    [{ ts: 0, project: "fireemu-oracle-idp", taskId: "AUTH-MFA-SANDBOX", event: "note" }],
    [
      {
        ts: "2026-02-30T12:00:00Z",
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

test("production recording requires the reviewed shared ledger lock before credentials", async () => {
  const dir = await mkdtemp(join(tmpdir(), "atb-direct-recording-"));
  try {
    const ledger = join(dir, "ledger.jsonl");
    await writeFile(ledger, "");
    const result = spawnSync(
      process.execPath,
      [join(import.meta.dirname, "auth-tenant-blocking/run.mjs"), "record-production"],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          FIREEMU_SANDBOX_LEDGER: ledger,
          FIREEMU_AUTH_TENANT_PRIVATE_DIR: dir,
          FIREEMU_AUTH_SANDBOX_WEB_CONFIG: "",
        },
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /reviewed shared sandbox ledger|reviewed sandbox lock/);
    assert.equal(await readFile(ledger, "utf8"), "");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a runner child process cannot inherit the reviewed lock capability", async () => {
  const dir = await mkdtemp(join(tmpdir(), "atb-child-env-"));
  try {
    const ledger = join(dir, "ledger.jsonl");
    const marker = join(dir, "git-env.txt");
    await writeFile(ledger, "");
    await writeFile(
      join(dir, "git"),
      "#!/bin/sh\nprintf '%s' \"${FIREEMU_SANDBOX_LOCK_NONCE-unset}\" > \"$ATB_MARKER\"\nprintf '/tmp/fake/.git\\n'\n",
      { mode: 0o700 },
    );
    const result = spawnSync(
      process.execPath,
      [join(import.meta.dirname, "auth-tenant-blocking/run.mjs"), "record-production"],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${dir}:${process.env.PATH}`,
          ATB_MARKER: marker,
          FIREEMU_SANDBOX_LOCK_NONCE: "a".repeat(64),
          FIREEMU_SANDBOX_WRAPPER_PID: String(process.pid),
          FIREEMU_AUTH_CAMPAIGN_PID: String(process.pid),
          FIREEMU_SANDBOX_LEDGER: ledger,
          FIREEMU_AUTH_TENANT_PRIVATE_DIR: dir,
        },
      },
    );
    assert.notEqual(result.status, 0);
    assert.equal(await readFile(marker, "utf8"), "unset");
    assert.equal(await readFile(ledger, "utf8"), "");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the reviewed lock binds its ledger, nonce, wrapper, and campaign process", async () => {
  const dir = await mkdtemp(join(tmpdir(), "atb-reviewed-lock-"));
  try {
    const ledger = join(dir, "ledger.jsonl");
    const nonce = "a".repeat(64);
    await writeFile(ledger, "");
    await writeFile(
      `${ledger}.lock`,
      JSON.stringify({
        pid: process.pid,
        nonceSha256: createHash("sha256").update(nonce).digest("hex"),
      }),
    );
    await assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid);
    await assert.rejects(
      assertReviewedLock(ledger, ledger, "b".repeat(64), process.pid, process.ppid),
      /lock owner/,
    );
    await assert.rejects(
      assertReviewedLock(ledger, ledger, nonce, process.pid + 1, process.ppid),
      /lock owner/,
    );
    await assert.rejects(
      assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid + 1),
      /process chain/,
    );
    await assert.rejects(
      assertReviewedLock(ledger, join(dir, "other.jsonl"), nonce, process.pid, process.ppid),
      /shared sandbox ledger/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
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

test("a restored recording retains its campaign reservation in later budget admission", async () => {
  const old = new Date(Date.now() - 2 * 3_600_000).toISOString();
  const rows = [
    {
      ts: old,
      project: "fireemu-oracle-idp",
      taskId: TASK_ID,
      event: "finished",
      outcome: "recorded",
      estimatedUsd: 8.5,
    },
    productionStartedRow({ ts: old, gitSha: "a".repeat(40), programs: ["sample"] }),
    {
      ts: old,
      project: "fireemu-oracle-idp",
      taskId: TASK_ID,
      event: "finished",
      outcome: "restored-by-hand",
      sandboxAtBaseline: true,
    },
  ];
  const result = await admitLocal(rows);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /budget/);
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
