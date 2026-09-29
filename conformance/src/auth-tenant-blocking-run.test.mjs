import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  assertReviewedLock,
  deployFixture,
  recordingStartedAt,
  productionStartedRow,
  otherLaneOnSandbox,
  recentAbort,
  restoreDue,
  restoreSandbox,
  localSessionEnv,
  runnerEnvironment,
  runnerSha256,
  selectRunner,
  TASK_ID,
} from "./auth-tenant-blocking/run.mjs";
import { createRequestBudget, installBudget } from "./auth-tenant-blocking/budget.mjs";

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

test("the reviewed project lock binds its file, nonce and processes, and no shared lock stands", async () => {
  // Project-scoped locks (owner decision A, 2026-09-28), used by the blocking suite.
  const dir = await mkdtemp(join(tmpdir(), "atb-project-lock-"));
  try {
    const ledger = join(dir, "ledger.jsonl");
    const nonce = "a".repeat(64);
    await writeFile(ledger, "");
    await mkdir(join(dir, "sandbox-locks"), { mode: 0o700 });
    const lock = join(dir, "sandbox-locks", "fireemu-oracle-idp.lock");
    const scope = { project: "fireemu-oracle-idp" };
    await writeFile(
      lock,
      `${JSON.stringify({
        taskId: "AUTH-BLOCKING-SANDBOX",
        packetId: "blocking-record",
        sourceCommit: "c".repeat(40),
        pid: process.pid,
        nonceSha256: createHash("sha256").update(nonce).digest("hex"),
        acquiredAt: "2026-09-28T00:00:00.000Z",
      })}\n`,
    );
    await assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid, scope);
    await assert.rejects(
      assertReviewedLock(ledger, ledger, "b".repeat(64), process.pid, process.ppid, scope),
      /lock owner/,
    );
    await assert.rejects(
      assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid, {
        project: "fireemu-oracle-sbx",
      }),
      /ENOENT/,
    );
    // The shared lock is not a project lock's stand-in, and while it stands nothing starts.
    await assert.rejects(
      assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid),
      /ENOENT/,
    );
    await writeFile(`${ledger}.lock`, "FS-RULES\n");
    await assert.rejects(
      assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid, scope),
      /legacy shared lock/,
    );
    await assert.rejects(
      assertReviewedLock(ledger, ledger, nonce, process.pid, process.ppid, {
        project: "../escape",
      }),
      /not a project ID/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("local admission skips another lane's unknown event and refuses its own", async () => {
  const ts = new Date(Date.now() - 2 * 3_600_000).toISOString();
  const foreign = { ts, project: "fireemu-oracle-idp", taskId: "AUTH-FEDERATION-SANDBOX" };
  for (const suite of ["tenant", "blocking"]) {
    const result = await admitLocal(
      [
        { ...foreign, event: "started" },
        { ...foreign, event: "progress", requests: { api: 9 } },
        { ...foreign, outcome: "recorded" },
      ],
      suite,
    );
    assert.equal(result.status, 0, `${suite}: ${result.stderr}`);
  }
  for (const taskId of [
    "AUTH-TENANT-SANDBOX",
    "AUTH-BLOCKING-SANDBOX",
    "AUTH-TENANT-SANDBOX-IAM",
    "AUTH-BLOCKING-SANDBOX-IAM",
    undefined,
    "",
  ]) {
    for (const suite of ["tenant", "blocking"]) {
      const result = await admitLocal(
        [{ ts, project: "fireemu-oracle-idp", taskId, event: "progress" }],
        suite,
      );
      assert.notEqual(result.status, 0, `${suite}: ${taskId}`);
      assert.match(result.stderr, /no recognized state/, `${suite}: ${taskId}`);
    }
  }
  // An unknown event does not excuse a malformed outcome or event.
  for (const fields of [
    { event: "progress", outcome: "" },
    { event: "progress", outcome: 7 },
    { event: "" },
  ]) {
    const result = await admitLocal([{ ...foreign, ...fields }]);
    assert.notEqual(result.status, 0, JSON.stringify(fields));
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

test("another lane's unknown event neither opens nor closes its hold (ledger 2026-09-28)", () => {
  const now = Date.now();
  const row = (age, fields) =>
    JSON.stringify({
      ts: new Date(now - age).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: "AUTH-FEDERATION-SANDBOX",
      ...fields,
    });
  const progress = (age) => row(age, { event: "progress", action: "record-oidc", step: "sent" });
  // The rows AUTH-FEDERATION's record-oidc wrote: a progress line keeps the start open.
  const started = `${row(3 * 3_600_000, { event: "started" })}\n${progress(2 * 3_600_000)}\n`;
  assert.match(otherLaneOnSandbox(started, now), /has not finished/);
  assert.equal(recentAbort(started, now), undefined);
  // It does not close the hold either when it carries an outcome.
  const withOutcome = `${started}${row(2 * 3_600_000, { event: "progress", outcome: "recorded" })}\n`;
  assert.match(otherLaneOnSandbox(withOutcome, now), /has not finished/);
  const closed = `${started}${row(3_000_000, { outcome: "recorded" })}\n`;
  assert.equal(otherLaneOnSandbox(closed, now), undefined);
  // Alone, it opens nothing, but it is still a recent line of that lane.
  assert.equal(otherLaneOnSandbox(`${progress(31 * 60_000)}\n`, now), undefined);
  assert.match(otherLaneOnSandbox(`${closed}${progress(10 * 60_000)}\n`, now), /wrote a line/);
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
      restoreSandbox({ ledger, isRecordingRunning: async () => false, lockCheck: async () => {} }),
      /another lane is on the sandbox/,
    );
    await writeFile(ledger, `${row(TASK_ID, { event: "started" })}\n${iamOnly}`);
    await assert.rejects(
      restoreSandbox({
        ledger,
        isRecordingRunning: async () => false,
        lockCheck: async () => {},
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
      lockCheck: async () => {},
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
          lockCheck: async () => {},
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

test("restore-sandbox runs only under the reviewed lock and holds the sandbox before writing", async () => {
  const now = Date.now();
  const row = (fields) =>
    JSON.stringify({
      ts: new Date(now - 60_000).toISOString(),
      project: "fireemu-oracle-idp",
      taskId: TASK_ID,
      ...fields,
    });
  // A clean hand restore closes the run: it is not due again.
  assert.equal(
    restoreDue(`${row({ event: "started" })}\n${row({ outcome: "restored-by-hand" })}\n`),
    false,
  );
  const dir = await mkdtemp(join(tmpdir(), "atb-restore-lock-"));
  const ledger = join(dir, "ledger.jsonl");
  try {
    await writeFile(ledger, `${row({ event: "started" })}\n`, { mode: 0o600 });
    let reached = false;
    await assert.rejects(
      restoreSandbox({
        ledger,
        isRecordingRunning: async () => false,
        lockCheck: async () => {
          throw new Error("no reviewed lock");
        },
        webConfig: async () => {
          reached = true;
          return {};
        },
      }),
      /no reviewed lock/,
    );
    assert.equal(reached, false);
    const lines = [];
    await assert.rejects(
      restoreSandbox({
        ledger,
        isRecordingRunning: async () => false,
        lockCheck: async () => {},
        webConfig: async () => ({ projectNumber: "123456789012" }),
        context: async () => {
          // The hold is in the ledger before the first request can be sent.
          lines.push(
            ...(await readFile(ledger, "utf8"))
              .trim()
              .split("\n")
              .map((l) => JSON.parse(l)),
          );
          throw new Error("stop");
        },
      }),
      /stop/,
    );
    const hold = lines.at(-1);
    assert.equal(hold.event, "started");
    assert.equal(hold.taskId, TASK_ID);
    assert.match(hold.reason, /restore-sandbox/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the signJwt preflight waits for a new binding to propagate, within a bound (review MF-1)", async () => {
  const { waitForSigner } = await import("./auth-tenant-blocking/run.mjs");
  const { SIGNER_READY_ATTEMPTS } = await import("./auth-tenant-blocking/budget.mjs");
  const waits = [];
  const sleep = async (ms) => waits.push(ms);
  const answers = (statuses) => {
    let sent = 0;
    return {
      send: async () => statuses[Math.min((sent += 1) - 1, statuses.length - 1)],
      sent: () => sent,
    };
  };
  // Refused while the binding propagates, then admitted: the recording can start.
  const late = answers([403, 403, 403, 200]);
  assert.equal(await waitForSigner(late.send, { sleep }), 4);
  assert.equal(late.sent(), 4);
  assert.deepEqual(waits, [30_000, 30_000, 30_000]);
  // Never admitted: the preflight stops after the last attempt and sends nothing more.
  waits.length = 0;
  const never = answers([403]);
  await assert.rejects(waitForSigner(never.send, { sleep }), /HTTP 403 after 20 attempts/);
  assert.equal(never.sent(), SIGNER_READY_ATTEMPTS);
  assert.equal(waits.length, SIGNER_READY_ATTEMPTS - 1);
  // Any other answer is not propagation: it stops at once.
  for (const status of [400, 401, 404, 429, 500]) {
    const other = answers([status, 200]);
    await assert.rejects(
      waitForSigner(other.send, { sleep }),
      new RegExp(`HTTP ${status} after 1`),
    );
    assert.equal(other.sent(), 1);
  }
  // A refused charge (the budget) is not retried either.
  let charged = 0;
  const refused = async () => {
    charged += 1;
    throw Object.assign(new Error("request budget: work request 1572 would pass 1571"), {
      fatal: true,
    });
  };
  await assert.rejects(waitForSigner(refused, { sleep }), /request budget/);
  assert.equal(charged, 1);
});

test("a runner that stops before its started line still records what it charged (review SF-1)", async () => {
  const { assertLedgerAdmission, unstartedRunnerRow } =
    await import("./auth-tenant-blocking/run.mjs");
  const row = unstartedRunnerRow({
    ts: "2026-09-27T12:00:00.000Z",
    budget: { total: 1800, cleanupReserve: 229, used: 45, refused: 0 },
    error: new Error("signJwt preflight: HTTP 403 after 20 attempts"),
  });
  assert.deepEqual(row, {
    ts: "2026-09-27T12:00:00.000Z",
    event: "control",
    taskId: "AUTH-TENANT-SANDBOX",
    project: "fireemu-oracle-idp",
    beforeStarted: true,
    reason: "the runner stopped before its started line; nothing on the sandbox changed",
    requests: 45,
    requestCountSemantics: "charged before each request; a gcloud token call counts 3",
    budget: { total: 1800, cleanupReserve: 229, used: 45, refused: 0 },
    error: "signJwt preflight: HTTP 403 after 20 attempts",
  });
  // A control line is neither a run nor an abort: it holds nothing and costs nothing.
  const ledger = `${JSON.stringify(row)}\n`;
  assert.equal(recentAbort(ledger, Date.parse(row.ts) + 1000), undefined);
  assertLedgerAdmission(ledger, Date.parse(row.ts) + 1000);
  assert.equal(
    unstartedRunnerRow({ ts: row.ts, budget: row.budget, error: "x".repeat(500) }).error.length,
    200,
  );
});

test("the signJwt preflight is work, even inside a cleanup phase (review-2 Should-2)", async () => {
  const { waitForSigner } = await import("./auth-tenant-blocking/run.mjs");
  const { currentKind, withPhase } = await import("./auth-tenant-blocking/budget.mjs");
  const kinds = [];
  const send = async () => {
    kinds.push(currentKind());
    return kinds.length < 3 ? 403 : 200;
  };
  await withPhase("cleanup", () => waitForSigner(send, { sleep: async () => {} }));
  assert.deepEqual(kinds, ["work", "work", "work"]);
});

test("a signal stops the signJwt wait before the next attempt (review-2 Should-3)", async () => {
  const { waitForSigner } = await import("./auth-tenant-blocking/run.mjs");
  const controller = new AbortController();
  let sent = 0;
  const send = async () => {
    sent += 1;
    // The signal arrives while the preflight waits for the binding.
    setTimeout(() => controller.abort(), 20);
    return 403;
  };
  const started = Date.now();
  await assert.rejects(
    waitForSigner(send, { signal: controller.signal, intervalMs: 60_000 }),
    /stopped by a signal before the recording started/,
  );
  assert.equal(sent, 1);
  assert.ok(Date.now() - started < 5_000, "the wait ended at the signal");
  // An already stopped runner sends nothing.
  await assert.rejects(waitForSigner(send, { signal: controller.signal }), /stopped by a signal/);
  assert.equal(sent, 1);
});

test("the budget wiring notes only a runner that stopped before its started line (review-2 Should-2)", async () => {
  const { appendStartedLine, underCampaignBudget } = await import("./auth-tenant-blocking/run.mjs");
  const dir = await mkdtemp(join(tmpdir(), "atb-wiring-"));
  const ledger = join(dir, "ledger.jsonl");
  await writeFile(ledger, "");
  const target = { fetch: async () => new Response("{}") };
  const run = async (body) => {
    const notes = [];
    const budget = createRequestBudget({ total: 100, cleanupReserve: 10 });
    const outcome = await underCampaignBudget(budget, body, {
      target,
      onUnstarted: async (error) => notes.push([budget.used(), error.message]),
    }).then(
      () => "done",
      (error) => error.message,
    );
    return { notes, outcome, budget };
  };
  // Charged, then stopped before the started line: one note with what it charged.
  const early = await run(async () => {
    await target.fetch("https://iamcredentials.googleapis.com/");
    await target.fetch("https://iamcredentials.googleapis.com/");
    throw new Error("signJwt preflight: HTTP 403 after 20 attempts");
  });
  assert.deepEqual(early.notes, [[2, "signJwt preflight: HTTP 403 after 20 attempts"]]);
  assert.match(early.outcome, /HTTP 403/);
  // Stopped after the started line: the terminal line accounts for it, no note.
  const late = await run(async (progress) => {
    await target.fetch("https://identitytoolkit.googleapis.com/");
    await appendStartedLine(ledger, { event: "started" }, progress);
    throw new Error("program failed");
  });
  assert.deepEqual(late.notes, []);
  assert.deepEqual(
    (await readFile(ledger, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line)),
    [{ event: "started" }],
  );
  // Nothing charged: nothing to note. A finished run: no note.
  assert.deepEqual((await run(async () => Promise.reject(new Error("local")))).notes, []);
  assert.deepEqual((await run(async () => undefined)).notes, []);
  // The budget is uninstalled on every path.
  const again = createRequestBudget({ total: 100, cleanupReserve: 10 });
  const restore = installBudget(again, target);
  restore();
});

test("a stop during the preflight deploys nothing (review S4)", async () => {
  const events = [];
  const controller = new AbortController();
  const deployer = {
    cliVersion: async () => "15.28.2",
    preflight: async () => {
      events.push("preflight");
      controller.abort();
      return {};
    },
    deploy: async () => events.push("deploy"),
  };
  const fixture = { deployed: false };
  await assert.rejects(
    deployFixture(fixture, deployer, {
      signal: controller.signal,
      buildDir: "/nonexistent",
      onDeploy: () => events.push("deadline"),
    }),
    /before the deployment/,
  );
  assert.deepEqual(events, ["preflight"]);
  assert.equal(fixture.deployed, false);
  // Without a stop the deadline starts, then the deployment.
  const clean = { deployed: false };
  const preflight = async () => (events.push("preflight"), {});
  const signal = new AbortController().signal;
  const onDeploy = () => events.push("deadline");
  await deployFixture(clean, { ...deployer, preflight }, { signal, buildDir: "/x", onDeploy });
  assert.deepEqual(events.slice(1), ["preflight", "deadline", "deploy"]);
  assert.equal(clean.deployed, true);
  assert.equal(clean.cli, "15.28.2");
});

test("restore-sandbox charges every request to its own budget and records it", async () => {
  const now = Date.now();
  const dir = await mkdtemp(join(tmpdir(), "atb-restore-budget-"));
  const ledger = join(dir, "ledger.jsonl");
  const started = JSON.stringify({
    ts: new Date(now - 60_000).toISOString(),
    project: "fireemu-oracle-idp",
    taskId: TASK_ID,
    event: "started",
  });
  try {
    await writeFile(ledger, `${started}\n`, { mode: 0o600 });
    let sent = 0;
    const target = { fetch: async () => ((sent += 1), new Response("{}")) };
    await assert.rejects(
      restoreSandbox({
        ledger,
        isRecordingRunning: async () => false,
        lockCheck: async () => {},
        webConfig: async () => ({ projectNumber: "123456789012" }),
        budgetTotal: 3,
        fetchTarget: target,
        context: async () => {
          for (let i = 0; i < 5; i += 1) await target.fetch("https://example.invalid/");
        },
      }),
      /request budget/,
    );
    assert.equal(sent, 3, "the fourth request was refused before it was sent");
    const lines = (await readFile(ledger, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const terminal = lines.find((line) => line.outcome === "restore-failed");
    assert.equal(terminal.requests, 3);
    assert.deepEqual(terminal.budget, { total: 3, cleanupReserve: 0, used: 3, refused: 1 });
    assert.equal(lines.at(-1).event, "started", "the failed restore keeps the sandbox hold");
    // The budget is uninstalled: a later request is not charged.
    await target.fetch("https://example.invalid/");
    assert.equal(sent, 4);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a restore dates the leftovers by the recording's own start line (review-2 S-B)", () => {
  const row = (fields) =>
    JSON.stringify({ project: "fireemu-oracle-idp", taskId: TASK_ID, ...fields });
  const ledger = [
    row({ ts: "2026-09-28T08:00:00.000Z", event: "started", gitSha: "a", programs: ["x"] }),
    row({ ts: "2026-09-28T08:30:00.000Z", outcome: "recorded" }),
    row({ ts: "2026-09-28T09:00:00.000Z", event: "started", gitSha: "b", programs: ["x"] }),
    // The campaign's hold and another task's start are not the recording's.
    row({
      ts: "2026-09-28T09:40:00.000Z",
      event: "started",
      reason: "runner sandbox cleanup uncertain",
    }),
    JSON.stringify({
      ts: "2026-09-28T09:50:00.000Z",
      event: "started",
      taskId: "OTHER",
      project: "fireemu-oracle-idp",
      gitSha: "c",
      programs: [],
    }),
    "not json",
  ].join("\n");
  assert.equal(recordingStartedAt(ledger)?.toISOString(), "2026-09-28T09:00:00.000Z");
  assert.equal(recordingStartedAt(""), undefined);
  assert.equal(
    recordingStartedAt(row({ event: "started", gitSha: "a", programs: [], ts: "later" })),
    undefined,
  );
});

test("a blocking restore adopts the leftovers of the recording that stopped (review-2 S-B)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "atb-restore-adopt-"));
  const ledger = join(dir, "ledger.jsonl");
  const started = new Date(Date.now() - 600_000).toISOString();
  await writeFile(
    ledger,
    `${JSON.stringify({ ts: started, event: "started", taskId: TASK_ID, project: "fireemu-oracle-idp", gitSha: "a", programs: ["x"] })}\n`,
    { mode: 0o600 },
  );
  const adopted = [];
  try {
    await assert.rejects(
      restoreSandbox({
        ledger,
        isRecordingRunning: async () => false,
        lockCheck: async () => {},
        webConfig: async () => ({ projectNumber: "123456789012" }),
        context: async () => ({}),
        sessionFactory: () => ({ counts: () => ({ harnessRequests: 0 }) }),
        suite: "blocking",
        fixtureDeployer: () => ({
          adoptLeftovers: (since) => adopted.push(since),
          remove: async () => {
            throw new Error("stop after adoption");
          },
        }),
      }),
      /stop after adoption/,
    );
    assert.deepEqual(
      adopted.map((since) => since?.toISOString()),
      [started],
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a comparison of blocking programs needs every fixture function served (closure review S4)", async () => {
  const { fixtureExports, unservedFixtureFunctions } =
    await import("./auth-tenant-blocking/run.mjs");
  const exported = fixtureExports(
    await readFile(join(import.meta.dirname, "auth-tenant-blocking/function/index.js"), "utf8"),
  );
  assert.deepEqual(exported, [
    "atbBeforeCreate",
    "atbBeforeSendEmail",
    "atbBeforeSendSms",
    "atbBeforeSignIn",
  ]);
  const all =
    "functions loaded: atbBeforeCreate, atbBeforeSignIn, atbBeforeSendEmail, atbBeforeSendSms\n";
  assert.equal(unservedFixtureFunctions(all, exported), undefined);
  // Another runner that ignores the mail functions, or a codebase without its dependencies.
  assert.match(
    unservedFixtureFunctions("functions loaded: atbBeforeCreate, atbBeforeSignIn\n", exported),
    /atbBeforeSendEmail, atbBeforeSendSms/,
  );
  assert.match(unservedFixtureFunctions("runner exited\n", exported), /loaded no functions/);
});

test("a comparison's evidence is bound to the fixture it was checked against (closure review S4)", async () => {
  const { comparisonEvidence } = await import("./auth-tenant-blocking/run.mjs");
  const comparison = {
    artifactSha256: "a".repeat(64),
    fixtureSha256: "f".repeat(64),
    runnerSha256: "r".repeat(64),
    sourceCommit: "c".repeat(40),
    treeClean: true,
    suite: "tenant",
    summary: { MATCH: 1 },
    rows: [{ row: "atb/tenant/manage#x", status: "MATCH", production: {}, fireemu: {} }],
  };
  const evidence = comparisonEvidence(comparison, "f".repeat(64), "tenant");
  assert.equal(evidence.fixtureSha256, "f".repeat(64));
  assert.equal(evidence.runnerSha256, "r".repeat(64));
  assert.equal(evidence.sourceCommit, "c".repeat(40));
  assert.deepEqual(evidence.rows, [{ row: "atb/tenant/manage#x", status: "MATCH" }]);
  assert.throws(() => comparisonEvidence(comparison, "e".repeat(64), "tenant"), /fixture changed/);
  // A leftover comparison of the other suite is not exported under this one.
  assert.throws(() => comparisonEvidence(comparison, "f".repeat(64), "blocking"), /tenant suite/);
});

// --- the Functions runner a comparison session runs ----------------------------------------------

const CHECKOUT_RUNNER = "/checkout/tools/runner-node/index.mjs";
const runnerCase = (env, files = []) => {
  const present = new Set(files);
  return runnerEnvironment(env, "/install/bin/fireemu", {
    checkoutDir: "/checkout/tools/runner-node",
    exists: (path) => present.has(path),
    realpath: (path) => path,
  });
};

test("without the packaged-runner switch a comparison session runs the checkout's runner", () => {
  assert.equal(runnerCase({ PATH: "/bin" }).FIREEMU_RUNNER_NODE, CHECKOUT_RUNNER);
  assert.equal(runnerCase({ AUTH_TENANT_PACKAGED_RUNNER: "0" }).FIREEMU_RUNNER_NODE, CHECKOUT_RUNNER);
});

test("with the packaged-runner switch the session runs the runner beside the binary", () => {
  const env = runnerCase({ PATH: "/bin", AUTH_TENANT_PACKAGED_RUNNER: "1" }, [
    "/install/bin/runner-node/index.mjs",
  ]);
  assert.equal("FIREEMU_RUNNER_NODE" in env, false);
  assert.equal(env.PATH, "/bin");
});

test("the packaged-runner switch drops a runner override the caller had set", () => {
  const env = runnerCase(
    { FIREEMU_RUNNER_NODE: "/elsewhere/index.mjs", AUTH_TENANT_PACKAGED_RUNNER: "1" },
    ["/install/bin/runner-node/index.mjs"],
  );
  assert.equal("FIREEMU_RUNNER_NODE" in env, false);
});

test("the packaged-runner switch accepts the runner one level above the binary, as the daemon does", () => {
  const env = runnerCase({ AUTH_TENANT_PACKAGED_RUNNER: "1" }, ["/install/runner-node/index.mjs"]);
  assert.equal("FIREEMU_RUNNER_NODE" in env, false);
});

test("the packaged-runner switch refuses to fall back when no runner ships beside the binary", () => {
  assert.throws(
    () => runnerCase({ AUTH_TENANT_PACKAGED_RUNNER: "1" }, [CHECKOUT_RUNNER]),
    /packaged runner.*\/install\/bin\/runner-node\/index\.mjs/,
  );
});

test("the packaged-runner switch resolves a symlinked binary before it looks beside it", () => {
  const env = runnerEnvironment({ AUTH_TENANT_PACKAGED_RUNNER: "1" }, "/install/.bin/fireemu", {
    checkoutDir: "/checkout/tools/runner-node",
    exists: (path) => path === "/install/pkg/bin/runner-node/index.mjs",
    realpath: () => "/install/pkg/bin/fireemu",
  });
  assert.equal("FIREEMU_RUNNER_NODE" in env, false);
});

test("the runner a session runs is named with its directory, packaged or checkout", () => {
  const present = new Set(["/install/bin/runner-node/index.mjs"]);
  const deps = { checkoutDir: "/checkout/tools/runner-node", exists: (p) => present.has(p), realpath: (p) => p };
  assert.deepEqual(selectRunner({}, "/install/bin/fireemu", deps), {
    source: "checkout",
    dir: "/checkout/tools/runner-node",
  });
  assert.deepEqual(selectRunner({ AUTH_TENANT_PACKAGED_RUNNER: "1" }, "/install/bin/fireemu", deps), {
    source: "packaged",
    dir: "/install/bin/runner-node",
  });
  assert.throws(
    () => selectRunner({ AUTH_TENANT_PACKAGED_RUNNER: "1" }, "/other/bin/fireemu", deps),
    /packaged runner/,
  );
});

const SESSION_PATHS = {
  inPath: "/run/programs.json",
  outPath: "/run/fireemu.json",
  signersPath: "/run/signers.json",
  run: "42",
  origin: "http://127.0.0.1:32298",
};
const sessionCase = (env, options = {}, files = []) => {
  const present = new Set(files);
  return localSessionEnv(env, "/install/bin/fireemu", {
    ...SESSION_PATHS,
    functions: true,
    checkoutDir: "/checkout/tools/runner-node",
    exists: (p) => present.has(p),
    realpath: (p) => p,
    ...options,
  });
};

test("the session environment carries the run's paths and the caller's environment", () => {
  const env = sessionCase({ PATH: "/bin", HOME: "/h" });
  assert.deepEqual(
    {
      in: env.AUTH_TENANT_IN,
      out: env.AUTH_TENANT_OUT,
      signers: env.AUTH_TENANT_SIGNERS,
      run: env.AUTH_TENANT_RUN,
      origin: env.AUTH_TENANT_ORIGIN,
      path: env.PATH,
      home: env.HOME,
    },
    {
      in: "/run/programs.json",
      out: "/run/fireemu.json",
      signers: "/run/signers.json",
      run: "42",
      origin: "http://127.0.0.1:32298",
      path: "/bin",
      home: "/h",
    },
  );
});

test("the session environment names the checkout runner only for a Functions session", () => {
  assert.equal(sessionCase({}).FIREEMU_RUNNER_NODE, CHECKOUT_RUNNER);
  assert.equal("FIREEMU_RUNNER_NODE" in sessionCase({}, { functions: false }), false);
});

test("the session environment of a packaged run has no runner override, or the session does not start", () => {
  const packaged = { AUTH_TENANT_PACKAGED_RUNNER: "1", FIREEMU_RUNNER_NODE: "/elsewhere/index.mjs" };
  const env = sessionCase(packaged, {}, ["/install/bin/runner-node/index.mjs"]);
  assert.equal("FIREEMU_RUNNER_NODE" in env, false);
  assert.equal(env.AUTH_TENANT_IN, "/run/programs.json");
  assert.throws(() => sessionCase(packaged, {}, []), /packaged runner/);
});

test("the runner digest covers the runner's sources and not its tests", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fireemu-runner-digest-"));
  try {
    await writeFile(join(dir, "index.mjs"), "a");
    await writeFile(join(dir, "helper.mjs"), "b");
    const base = await runnerSha256(dir);
    await writeFile(join(dir, "helper.test.mjs"), "t");
    await writeFile(join(dir, "notes.txt"), "n");
    assert.equal(await runnerSha256(dir), base);
    await writeFile(join(dir, "helper.mjs"), "c");
    assert.notEqual(await runnerSha256(dir), base);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the session's child environment and the comparison's runner digest go through the runner selection", async () => {
  const source = await readFile(new URL("./auth-tenant-blocking/run.mjs", import.meta.url), "utf8");
  // Only runnerEnvironment names the runner override (once to strip it, once to set it); the spawn uses the builder; the digest follows the choice.
  assert.equal(source.match(/FIREEMU_RUNNER_NODE/g).length, 2);
  assert.match(source, /env: localSessionEnv\(withoutLockCapability\(\), binary, \{/);
  assert.match(source, /runnerSha256: await runnerSha256\(selectRunner\(process\.env, local\.binary\)\.dir\)/);
});
