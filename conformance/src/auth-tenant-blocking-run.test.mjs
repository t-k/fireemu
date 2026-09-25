import assert from "node:assert/strict";
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
