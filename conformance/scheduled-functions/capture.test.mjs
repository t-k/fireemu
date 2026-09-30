import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, writeFile, lstat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { captureShape, harnessDigest } from "./capture.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);
const clock = () => new Date("2026-09-30T09:00:00Z");

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "fireemu-scheduled-shape-"));
  t.after(() => rm(root, { recursive: true }));
  const runs = join(root, "docs.local/runs");
  const lane = join(runs, "codex-lane8");
  const locks = join(runs, "sandbox-locks");
  await mkdir(lane, { recursive: true, mode: 0o700 });
  await mkdir(locks, { mode: 0o700 });
  await mkdir(join(root, "docs.local/instructions"));
  const guard = join(locks, "fireemu-oracle-sbx.recovery-guard");
  await writeFile(guard, "foreign guard", { mode: 0o600 });
  await writeFile(join(runs, "sandbox-ledger.jsonl"), "", { mode: 0o600 });
  const plan = {
    schemaVersion: 1,
    project: "fireemu-oracle-sbx",
    projectNumber: "123456789012",
    runId: "b1".repeat(8),
    sourceCommit,
    harnessDigest: await harnessDigest(),
    maxRequests: 64,
    reserveUsd: 1,
  };
  const packetPath = join(lane, "shape-packet.json");
  const bytes = JSON.stringify(plan);
  await writeFile(packetPath, bytes, { mode: 0o600 });
  const approval = `- 2026-09-30 | SCHEDULED-FUNCTIONS stage-2 shape packet | decision=APPROVE; packetSha256=${sha256(bytes)}; sourceCommit=${sourceCommit}; harnessDigest=${plan.harnessDigest}; maxRequests=64; reserveUsd=1 | Claude（調整役。委任） | private packet\n`;
  await writeFile(join(root, "docs.local/instructions/owner-decisions.md"), approval);
  let tokens = 0,
    sends = 0;
  const options = {
    root,
    packetPath,
    sourceCommit,
    coordinatorSend: true,
    clock,
    getToken: async () => {
      tokens++;
      const ledger = await readFile(join(runs, "sandbox-ledger.jsonl"), "utf8");
      assert.ok(ledger.includes('"event":"started"'));
      await lstat(join(locks, "fireemu-oracle-sbx.lock"));
      return "test-bearer";
    },
    send: async () => {
      sends++;
      return new Response("{}", { status: 403 });
    },
  };
  return { root, runs, locks, guard, options, counts: () => ({ tokens, sends }) };
}

test("concrete capture reserves durably before token and retains its project lock for shape review", async (t) => {
  const f = await fixture(t);
  const summary = await captureShape(f.options);
  assert.equal(summary.outcome, "shape-needs-review");
  assert.deepEqual(f.counts(), { tokens: 1, sends: 1 });
  await lstat(join(f.locks, "fireemu-oracle-sbx.lock"));
  assert.equal(await readFile(f.guard, "utf8"), "foreign guard");
  const ledger = await readFile(join(f.runs, "sandbox-ledger.jsonl"), "utf8");
  assert.ok(ledger.includes('"event":"needs-recovery"'));
  assert.ok(!ledger.includes("test-bearer"));
  const row = JSON.parse(
    await readFile(join(summary.directory, "requests.jsonl"), "utf8").then((s) => s.split("\n")[0]),
  );
  assert.equal(row.state, "before-send");
});

test("a held project or legacy lock fails before reservation, credentials and request", async (t) => {
  for (const name of ["project", "legacy"]) {
    const f = await fixture(t);
    const path =
      name === "project"
        ? join(f.locks, "fireemu-oracle-sbx.lock")
        : join(f.runs, "sandbox-ledger.jsonl.lock");
    await writeFile(path, "other owner");
    await assert.rejects(captureShape(f.options), /lock/);
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
    assert.equal(await readFile(path, "utf8"), "other owner");
    assert.equal(await readFile(join(f.runs, "sandbox-ledger.jsonl"), "utf8"), "");
  }
});

test("missing or revoked approval, stale source, and an unconfirmed coordinator call do not read credentials", async (t) => {
  for (const kind of ["missing", "revoked", "source", "flag"]) {
    const f = await fixture(t);
    const ownerPath = join(f.root, "docs.local/instructions/owner-decisions.md");
    if (kind === "missing") await writeFile(ownerPath, "");
    if (kind === "revoked") {
      const approval = await readFile(ownerPath, "utf8");
      await writeFile(
        ownerPath,
        approval + approval.replace("decision=APPROVE", "decision=REVOKED"),
      );
    }
    if (kind === "source") f.options.sourceCommit = "c".repeat(40);
    if (kind === "flag") f.options.coordinatorSend = false;
    await assert.rejects(captureShape(f.options));
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
  }
});

test("recent project activity and exhausted task budget fail under the lock without reserving", async (t) => {
  for (const kind of ["recent", "budget", "open"]) {
    const f = await fixture(t);
    const row = {
      ts: kind === "recent" ? clock().toISOString() : "2026-09-29T09:00:00Z",
      project: "fireemu-oracle-sbx",
      taskId: kind === "budget" ? "SCHEDULED-FUNCTIONS" : "OTHER",
      event: kind === "open" ? "started" : "finished",
      outcome: kind === "open" ? undefined : "recorded",
      sandboxAtBaseline: true,
      estimatedUsd: 10,
      attemptId: "old",
    };
    const ledger = JSON.stringify(row) + "\n";
    await writeFile(join(f.runs, "sandbox-ledger.jsonl"), ledger);
    await assert.rejects(captureShape(f.options));
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
    assert.equal(await readFile(join(f.runs, "sandbox-ledger.jsonl"), "utf8"), ledger);
    await assert.rejects(lstat(join(f.locks, "fireemu-oracle-sbx.lock")), { code: "ENOENT" });
  }
});

test("malformed task costs cannot create budget headroom", async (t) => {
  for (const amount of [-1, "1", null]) {
    const f = await fixture(t);
    const row = {
      ts: "2026-09-29T09:00:00Z",
      project: "fireemu-oracle-sbx",
      taskId: "SCHEDULED-FUNCTIONS",
      event: "finished",
      outcome: "recorded",
      estimatedUsd: amount,
      attemptId: "old",
    };
    await writeFile(join(f.runs, "sandbox-ledger.jsonl"), JSON.stringify(row) + "\n");
    await assert.rejects(captureShape(f.options), /budget/);
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
  }
});

for (const word of ["REVOKED", "WITHDRAWN", "SUPERSEDED"]) {
  for (const layout of ["conventional", "semicolon", "decision"]) {
    test(`a later ${word} ${layout} ledger line prevents reservation and credentials`, async (t) => {
      const f = await fixture(t);
      const ownerPath = join(f.root, "docs.local/instructions/owner-decisions.md");
      const approval = await readFile(ownerPath, "utf8");
      const digest = approval.match(/packetSha256=([a-f0-9]{64})/)[1];
      const body =
        layout === "conventional"
          ? `${word} packetSha256=${digest}（used）`
          : layout === "semicolon"
            ? `${word}; packetSha256=${digest}; reason=used`
            : `decision=${word}; packetSha256=${digest}`;
      await writeFile(
        ownerPath,
        approval + `- 2026-09-30 | SCHEDULED-FUNCTIONS withdrawal | ${body} | Claude | private\n`,
      );
      await assert.rejects(captureShape(f.options), /approval/);
      assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
      assert.equal(await readFile(join(f.runs, "sandbox-ledger.jsonl"), "utf8"), "");
      await assert.rejects(lstat(join(f.locks, "fireemu-oracle-sbx.lock")), { code: "ENOENT" });
    });
  }
}

test("approval must bind every source, budget and author field", async (t) => {
  for (const [before, after] of [
    ["sourceCommit=" + sourceCommit, "sourceCommit=" + "d".repeat(40)],
    ["harnessDigest=", "otherDigest="],
    ["maxRequests=64", "maxRequests=65"],
    ["reserveUsd=1", "reserveUsd=2"],
    ["Claude（調整役。委任）", "untrusted"],
    ["SCHEDULED-FUNCTIONS stage-2 shape packet", "SCHEDULED-FUNCTIONS another packet"],
  ]) {
    const f = await fixture(t);
    const ownerPath = join(f.root, "docs.local/instructions/owner-decisions.md");
    const approval = await readFile(ownerPath, "utf8");
    assert.ok(approval.includes(before));
    await writeFile(ownerPath, approval.replace(before, after));
    await assert.rejects(captureShape(f.options), /approval/);
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
  }
});
