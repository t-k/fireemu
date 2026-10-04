import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import * as sandbox from "./functions-events/record/sandbox.mjs";

const row = (over) =>
  JSON.stringify({
    ts: "2026-10-01T08:00:00Z",
    project: sandbox.PROJECT,
    taskId: sandbox.TASK_ID,
    ...over,
  });
const now = Date.parse("2026-10-04T12:00:00Z");
const clean = [
  row({ event: "started", runDir: "r1", estimatedUsd: 2 }),
  row({
    ts: "2026-10-01T08:30:00Z",
    event: "finished",
    outcome: "prepared",
    lockRetained: false,
    runDir: "r1",
    estimatedUsd: 2,
  }),
].join("\n");

test("a project whose last run ended prepared and kept no lock admits a new run", () => {
  assert.deepEqual(sandbox.ledgerProblems(clean, now), []);
});

test("an open run, a recent line, an unreadable time or a kept lock each refuse the start", () => {
  const open = `${clean}\n${row({ ts: "2026-10-02T00:00:00Z", event: "started", taskId: "OTHER-TASK" })}`;
  assert.ok(sandbox.ledgerProblems(open, now).some((p) => p.includes("OTHER-TASK")));
  // a run left open before the latest clean closing line is history, not a blocker
  const history = `${row({ ts: "2026-09-01T00:00:00Z", event: "started", taskId: "OLD-TASK" })}\n${clean}`;
  assert.deepEqual(sandbox.ledgerProblems(history, now), []);
  assert.ok(
    sandbox
      .ledgerProblems(row({ event: "started" }), now)
      .some((p) => p.includes("no clean closing line")),
  );
  assert.ok(
    sandbox
      .ledgerProblems(`${clean}\n${row({ ts: "2026-10-04T11:45:00Z", event: "note" })}`, now)
      .some((p) => p.includes("30 minutes")),
  );
  assert.ok(
    sandbox
      .ledgerProblems(`${clean}\n${row({ ts: "not a time", event: "note" })}`, now)
      .some((p) => p.includes("unreadable")),
  );
  const kept = [
    row({ event: "started" }),
    row({ event: "finished", outcome: "needs-recovery", lockRetained: true }),
  ].join("\n");
  assert.ok(sandbox.ledgerProblems(kept, now).some((p) => p.includes("did not end cleanly")));
  assert.deepEqual(
    sandbox.ledgerProblems(
      `${kept}\n${row({ ts: "2026-10-02T00:00:00Z", event: "cleanup-verified", sandboxAtBaseline: true })}`,
      now,
    ),
    [],
  );
});

test("lines of other projects do not matter", () => {
  const other = JSON.stringify({
    ts: "2026-10-04T11:59:00Z",
    project: "fireemu-oracle-idp",
    taskId: "X",
    event: "started",
  });
  assert.deepEqual(sandbox.ledgerProblems(`${clean}\n${other}`, now), []);
});

test("the budget counts each run once and refuses a reserve that passes the cap", () => {
  const spent = (usd) =>
    [
      row({ event: "started", runDir: "a", estimatedUsd: 2 }),
      row({ event: "finished", runDir: "a", estimatedUsd: 2 }),
      row({ event: "started", runDir: "b", estimatedUsd: usd }),
    ].join("\n");
  assert.deepEqual(sandbox.budgetProblems(spent(26)), []);
  assert.equal(sandbox.budgetProblems(spent(28.5)).length, 1);
  assert.equal(sandbox.budgetProblems(row({ event: "started", estimatedUsd: -1 })).length, 1);
  assert.equal(sandbox.budgetProblems(row({ event: "started", estimatedUsd: "2" })).length, 1);
});

const pins = {
  packetSha256: "a".repeat(64),
  harnessSha256: "b".repeat(64),
  sourceCommit: "c".repeat(40),
};
const E = `- 2026-10-04 | ${sandbox.ENVELOPE_TOPIC} | envelopeId=FE-FORMAL-1; project=fireemu-oracle-events; maxRequests=520; cliMax=2; reserveUsd=4.00 | オーナー | ledger 812`;
const V = `- 2026-10-04 | ${sandbox.TOPIC} | decision=APPROVE; envelopeId=FE-FORMAL-1; packetSha256=${pins.packetSha256}; harnessSha256=${pins.harnessSha256}; sourceCommit=${pins.sourceCommit} | Claude（委任。枠の内） | review`;

test("an envelope line and a version line that name the same pins approve the run", () => {
  assert.deepEqual(sandbox.approval(`${E}\n${V}`, pins).problems, []);
});

test("the approval is refused for another pin, a missing or smaller envelope, a revocation or an unknown decider", () => {
  const refused = (text, p = pins) => sandbox.approval(text, p).problems.length > 0;
  assert.ok(refused(V));
  assert.ok(refused(E));
  for (const key of Object.keys(pins))
    assert.ok(
      refused(`${E}\n${V}`, { ...pins, [key]: "d".repeat(key === "sourceCommit" ? 40 : 64) }),
      key,
    );
  for (const [from, to] of [
    ["maxRequests=520", "maxRequests=519"],
    ["cliMax=2", "cliMax=1"],
    ["reserveUsd=4.00", "reserveUsd=3.99"],
    ["project=fireemu-oracle-events", "project=other"],
  ])
    assert.ok(refused(`${E.replace(from, to)}\n${V}`), to);
  assert.ok(
    refused(
      `${E}\n${V}\n- 2026-10-05 | ${sandbox.TOPIC} | REVOKED packetSha256=${pins.packetSha256} | Claude（委任 | x`,
    ),
  );
  assert.ok(
    refused(
      `${E}\n${V}\n- 2026-10-05 | ${sandbox.ENVELOPE_TOPIC} | REVOKED envelopeId=FE-FORMAL-1 | Claude（委任 | x`,
    ),
  );
  assert.ok(refused(`${E}\n${V.replace("Claude（委任。枠の内）", "Codex")}`));
  assert.ok(refused(`${E.replace("オーナー", "Codex")}\n${V}`));
});

test("a packet whose run already started cannot start again", () => {
  assert.equal(
    sandbox.packetUsed(
      row({ event: "started", packetSha256: pins.packetSha256 }),
      pins.packetSha256,
    ),
    true,
  );
  assert.equal(sandbox.packetUsed(clean, pins.packetSha256), false);
});

test("the lock is exclusive, private, refused beside the legacy lock, and released only by its owner", () => {
  const dir = mkdtempSync(join(tmpdir(), "fe-lock-"));
  const lockDir = join(dir, "locks");
  const legacyLock = join(dir, "ledger.lock");
  const lock = sandbox.acquireLock({ lockDir, legacyLock, body: { pid: process.pid } });
  assert.throws(() => sandbox.acquireLock({ lockDir, legacyLock, body: {} }), /is held/);
  writeFileSync(lock.path, "tampered");
  assert.throws(() => sandbox.releaseLock(lock), /rewritten/);
  writeFileSync(lock.path, JSON.stringify({ pid: process.pid }));
  sandbox.releaseLock(lock);
  assert.equal(existsSync(lock.path), false);
  writeFileSync(legacyLock, "x");
  assert.throws(() => sandbox.acquireLock({ lockDir, legacyLock, body: {} }), /legacy/);
});

test("the ledger lines carry the packet, the envelope and the reserve; a kept lock is said", () => {
  const started = sandbox.startedLine({
    ts: "t",
    runDir: "r",
    packetSha256: pins.packetSha256,
    harnessSha256: pins.harnessSha256,
    gitSha: pins.sourceCommit,
    approval: { envelopeId: "FE-FORMAL-1" },
    lock: { sha256: "s" },
  });
  assert.deepEqual(
    [started.event, started.estimatedUsd, started.maxRequests, started.cliMax],
    ["started", 4, 520, 2],
  );
  const finished = sandbox.finishedLine({
    ts: "t",
    runDir: "r",
    packetSha256: pins.packetSha256,
    gitSha: pins.sourceCommit,
    outcome: "needs-recovery",
    requests: 400,
    cliAttempts: { deploy: 1, delete: 1 },
    lockRetained: true,
  });
  assert.equal(finished.lockRetained, true);
  const path = join(mkdtempSync(join(tmpdir(), "fe-led-")), "ledger.jsonl");
  sandbox.appendLedger(path, started);
  sandbox.appendLedger(path, finished);
  assert.equal(readFileSync(path, "utf8").trim().split("\n").length, 2);
});
