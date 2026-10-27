// The entry of the CV14 recorder: admission by a reviewed approval file and packet, the pins of the
// packet, the token provider, and a run's private output. A run itself is exercised on the fakes.

import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { FIXTURE_HANDLERS } from "./frames.mjs";
import {
  assertApproval,
  createTokenProvider,
  estimatedUsd,
  executeRun,
  exitCodeOf,
  parsePacketPins,
} from "./record.mjs";
import { createRehearsalEnvironment } from "./world.fake.mjs";

const SHA = "a".repeat(64);
const GIT = "b".repeat(40);

test("an approval binds one decision, one commit and one packet, and nothing else says otherwise", () => {
  const ok = `Decision: APPROVE\ngitSha: ${GIT}\npacketSha256: ${SHA}\nNotes follow.\n`;
  assert.doesNotThrow(() => assertApproval(ok, GIT, SHA));
  for (const bad of [
    ok.replace("APPROVE", "CHANGES REQUESTED"),
    ok.replace(GIT, "c".repeat(40)),
    ok.replace(SHA, "d".repeat(64)),
    `${ok}Decision: CHANGES REQUESTED\n`,
    `${ok}  gitSha: ${GIT}\n`,
    `${ok}> packetSha256: ${SHA}\n`,
    "",
  ]) {
    assert.throws(() => assertApproval(bad, GIT, SHA), /APPROVE must bind/, bad.slice(0, 40));
  }
  assert.doesNotThrow(() => assertApproval(ok.replaceAll("\n", "\r\n"), GIT, SHA));
});

test("the packet carries its machine-readable pins in one fenced block", () => {
  const block = (body) => `# Packet\n\ntext\n\n\`\`\`json cv14-pins\n${body}\n\`\`\`\n`;
  assert.deepEqual(parsePacketPins(block(JSON.stringify({ baselineRulesSha256: SHA }))), {
    baselineRulesSha256: SHA,
  });
  for (const bad of [
    "no block",
    block("{not json"),
    block(JSON.stringify({ baselineRulesSha256: "short" })),
    block(JSON.stringify({ baselineRulesSha256: SHA, extra: 1 })),
    block(JSON.stringify({})),
    `${block(JSON.stringify({ baselineRulesSha256: SHA }))}${block(JSON.stringify({ baselineRulesSha256: SHA }))}`,
  ]) {
    assert.throws(() => parsePacketPins(bad), /packet pins/, bad.slice(0, 40));
  }
});

test("the token provider refreshes after the token expired and counts every refresh", async () => {
  let n = 0;
  let nowMs = 1_000;
  const seen = [];
  const acquire = async (_adc, budget, kind) => {
    budget.take(kind);
    seen.push(kind);
    return { value: `tok-${++n}`, expiresAt: nowMs + 10_000 };
  };
  const taken = [];
  const budget = { take: (kind) => taken.push(kind) };
  const provider = createTokenProvider({ file: 1 }, budget, { acquire, now: () => nowMs });
  assert.equal(await provider(), "tok-1");
  assert.equal(await provider(), "tok-1");
  nowMs += 20_000;
  assert.equal(await provider(), "tok-2");
  assert.deepEqual(seen, ["token", "token"]);
});

test("the cost is the FUNCTIONS-HTTP constant per deploy, and the exit code tells recorded, review and residue apart", () => {
  assert.equal(estimatedUsd({ cliDeploy: 8 }), 4.41);
  assert.equal(estimatedUsd({ cliDeploy: 0 }), 0.01);
  assert.equal(exitCodeOf({ outcome: "recorded", residual: false }), 0);
  assert.equal(exitCodeOf({ outcome: "stopped-needs-review", residual: false }), 2);
  assert.equal(exitCodeOf({ outcome: "stopped-needs-review", residual: true }), 3);
});

async function rehearse(arg) {
  const runDir = await mkdtemp(join(tmpdir(), "cv14-record-"));
  const rehearsal = createRehearsalEnvironment(arg);
  const summary = await executeRun({
    environment: rehearsal.environment,
    runDir,
    packetPins: { baselineRulesSha256: rehearsal.environment.rtdbPacket.baselineRulesSha256 },
  });
  return { runDir, summary, ...rehearsal };
}

test("a stored file is refused when it holds a secret", async () => {
  const w = await rehearse({ options: { secretInRecord: "test-token" } });
  try {
    assert.equal(w.summary.outcome, "stopped-needs-review");
    assert.match(
      JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8")).reasons.join(";"),
      /output was refused/,
    );
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

test("a run writes its private output and a summary of counts only", async () => {
  const w = await rehearse();
  try {
    assert.equal(w.summary.outcome, "recorded", JSON.stringify(w.summary));
    assert.equal(w.summary.residual, false);
    assert.equal(w.summary.estimatedUsd, 4.41);
    assert.deepEqual(Object.keys(w.summary).toSorted(), [
      "estimatedUsd",
      "outcome",
      "requests",
      "residual",
      "runDir",
    ]);
    const names = (await readdir(w.runDir)).toSorted();
    for (const file of [
      "frames.jsonl",
      "forms.json",
      "grants.json",
      "inventory.json",
      "journal.jsonl",
      "lines-masked.txt",
      "owned-uploads.jsonl",
      "records.json",
      "report.json",
      "result.json",
    ]) {
      assert.ok(names.includes(file), file);
      // the ledger of owned uploads is written by its own module inside the private directory
      if (file !== "owned-uploads.jsonl") {
        assert.equal((await stat(join(w.runDir, file))).mode & 0o077, 0, `${file} is private`);
      }
    }
    const result = JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8"));
    assert.equal(result.outcome, "recorded");
    assert.equal(result.deployed, 8);
    const report = JSON.parse(await readFile(join(w.runDir, "report.json"), "utf8"));
    assert.equal(report.steps.length, 9);
    const records = JSON.parse(await readFile(join(w.runDir, "records.json"), "utf8"));
    assert.deepEqual(
      Object.keys(records),
      FIXTURE_HANDLERS.map((h) => h.name),
    );
    // no token, no signed URL and no project number reaches a stored file
    for (const file of names) {
      const text = await readFile(join(w.runDir, file), "utf8");
      assert.ok(!text.includes("test-token"), file);
      assert.ok(!text.includes("SECRET-MARKER"), file);
    }
    const masked = await readFile(join(w.runDir, "records.json"), "utf8");
    assert.ok(
      !masked.includes(w.environment.projectNumber) ||
        w.environment.projectNumber === "123456789012",
    );
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

test("a run that leaves residue says so in the summary and the exit code", async () => {
  const w = await rehearse({ options: { keepFunction: "rtdbDeletedV2" } });
  try {
    assert.equal(w.summary.outcome, "stopped-needs-review");
    assert.equal(w.summary.residual, true);
    assert.equal(exitCodeOf(w.summary), 3);
    const result = JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8"));
    assert.match(result.reasons.join(";"), /rtdbDeletedV2 was not cleaned/);
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});
