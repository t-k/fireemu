// One run of probe-v3 through the shared probe runner: admission, the rows, the closing row and
// what keeps the project lock. Every collaborator is a fake, and the production is the stateful
// fake of the probe-v3 tests, so nothing is sent.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { admissionProblems } from "./auth-fs-cross/sandbox.mjs";
import { production } from "./storage-object-probe3-fake.mjs";
import { encodeRow } from "./storage-object/ledger-rows.mjs";
import { PROBE_V2_KIT, PROBE_V3_KIT, probeRun } from "./storage-object/probe-run.mjs";
import { PROBE3_MAX_REQUESTS, PROBE3_RESERVE_USD } from "./storage-object/probe3.mjs";
import { RECORD_PROJECT } from "./storage-object/record.mjs";

const PINS = [
  "packetSha256",
  "sourceCommit",
  "runnerSha256",
  "planSha256",
  "corpusSha256",
  "rulesSourceSha256",
];
const COMMIT = "b".repeat(40);
const packet = {
  taskId: "STORAGE-OBJECT",
  packetName: "probe-v3",
  projectId: RECORD_PROJECT,
  maxRequests: PROBE3_MAX_REQUESTS,
  reserveUsd: PROBE3_RESERVE_USD,
  ...Object.fromEntries(
    PINS.map((key, index) => [key, `${index + 1}`.repeat(key === "sourceCommit" ? 40 : 64)]),
  ),
  sourceCommit: COMMIT,
};
const review = {
  verdict: "APPROVE",
  must: [],
  should: [],
  ...Object.fromEntries(PINS.map((key) => [key, packet[key]])),
  envelopeId: null,
  withinEnvelope: false,
};
const approvalText = `- 2026-10-01 | STORAGE-OBJECT probe-v3 | decision=APPROVE; ${PINS.map((key) => `${key}=${packet[key]}`).join("; ")} | オーナー（ローカル試験） | packet.md\n`;
const NOW = Date.parse("2026-10-02T09:00:00Z");
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";
const TOKEN = "ya29.synthetic-owner-access-token-value";

function setup(productionOptions = {}, overrides = {}) {
  const base = mkdtempSync(join(tmpdir(), "storage-object-probe3-run-"));
  const lockDir = join(base, "sandbox-locks");
  const events = [];
  const ledgerRows = [];
  let ledgerText = overrides.ledgerText ?? "";
  const privateFiles = { captures: [], events: [], meta: [] };
  const fake = production(productionOptions);
  const deps = {
    ids: { runId: RUN, otherRunId: OTHER },
    packet: overrides.packet ?? packet,
    review,
    ownerDecisionsText: approvalText,
    env: {},
    nodeVersion: "v24.14.0",
    ledger: {
      read: async () => ledgerText,
      append: async (row) => {
        events.push(`ledger-append:${row.event}${row.outcome ? `:${row.outcome}` : ""}`);
        ledgerRows.push(row);
        ledgerText += encodeRow(row);
      },
    },
    git: async () => ({ clean: true, commit: COMMIT }),
    admission: admissionProblems,
    locks: { lockDir, legacyLockPath: join(base, "sandbox-ledger.jsonl.lock"), pid: process.pid },
    privateRun: async () => ({
      dir: join(base, "private"),
      capture: async (record) => privateFiles.captures.push(record),
      event: async (event) => privateFiles.events.push(event),
      meta: async (value) => privateFiles.meta.push(value),
    }),
    getToken: async () => TOKEN,
    actualPins: Object.fromEntries(
      ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"].map((key) => [
        key,
        packet[key],
      ]),
    ),
    fetch: fake.fetchImpl,
    now: () => new Date(NOW),
  };
  return { deps, events, ledgerRows, privateFiles, lockDir, fake };
}

// The shipped kit spaces the writes to one object by a second; the tests use it without the wait.
const FAST = Object.freeze({
  ...PROBE_V3_KIT,
  pacer: () => ({ dispatch: (_name, attempt) => attempt() }),
});

const lockFiles = (s) => (existsSync(s.lockDir) ? readdirSync(s.lockDir) : []);

test("an honest run: started, the recording, removal, one closing row `recorded`, the lock released", async () => {
  const s = setup();
  const result = await probeRun(s.deps, FAST);
  assert.equal(result.outcome, "recorded");
  assert.equal(s.fake.store.size, 0);
  assert.equal(result.requests, s.fake.calls.length);
  assert.ok(result.requests <= 46);
  assert.deepEqual(s.events, ["ledger-append:started", "ledger-append:finished:recorded"]);
  const [started, closing] = s.ledgerRows;
  assert.equal(started.maxRequests, 60);
  assert.equal(started.estimatedUsd, 0.02);
  assert.equal(closing.requests, result.requests);
  assert.equal(closing.estimatedUsd, 0.02);
  assert.equal(closing.sandboxAtBaseline, true);
  assert.deepEqual(lockFiles(s), []);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.status, "PROBE_COMPLETE");
  assert.equal(meta.outcome, "recorded");
  assert.equal(meta.interrupted, undefined);
  assert.equal(meta.plan.prefix, `storage-object/${RUN}/`);
});

test("every request goes to a real host with the owner token and the quota project", async () => {
  const s = setup();
  await probeRun(s.deps, FAST);
  const hosts = new Set(s.fake.calls.map((call) => new URL(call.href).origin));
  assert.deepEqual([...hosts].toSorted(), [
    "https://firebasestorage.googleapis.com",
    "https://storage.googleapis.com",
  ]);
  for (const call of s.fake.calls) {
    assert.equal(call.headers.get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(call.headers.get("x-goog-user-project"), RECORD_PROJECT);
  }
});

test("when every recording step answers something unexpected, the run still closes on an empty prefix", async () => {
  const s = setup({ odd: true });
  const result = await probeRun(s.deps, FAST);
  assert.equal(result.outcome, "recorded");
  assert.equal(s.fake.store.size, 0);
  assert.equal(s.ledgerRows.at(-1).outcome, "recorded");
  assert.ok(s.privateFiles.meta.at(-1).answers.filter((row) => row.skipped).length >= 8);
});

test("a recording cut short, with the prefix read back empty, closes as stopped-clean and releases the lock", async () => {
  const s = setup({ failAt: 16 });
  const result = await probeRun(s.deps, FAST);
  assert.equal(result.outcome, "stopped-clean");
  assert.equal(s.fake.store.size, 0);
  const closing = s.ledgerRows.at(-1);
  assert.equal(closing.event, "finished");
  assert.equal(closing.estimatedUsd, 0.02);
  assert.equal(closing.outcome, "stopped-clean");
  assert.equal(closing.sandboxAtBaseline, true);
  assert.deepEqual(lockFiles(s), []);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.status, "PROBE_INTERRUPTED");
  assert.equal(meta.outcome, "stopped-clean");
  assert.match(meta.interrupted.reason, /fetch failed/);
});

test("an object left under the prefix is needs-recovery, the lock is kept, and the meta says where", async () => {
  const stuckName = `storage-object/${RUN}/probe3/gcs/resumable.bin`;
  const s = setup({ deleteFails: stuckName });
  await assert.rejects(probeRun(s.deps, FAST), (error) => {
    assert.equal(error.afterStart, true);
    assert.match(error.message, /not read back as empty/);
    return true;
  });
  assert.ok(s.fake.store.has(stuckName));
  const closing = s.ledgerRows.at(-1);
  assert.equal(closing.event, "needs-recovery");
  assert.equal(closing.estimatedUsd, 0.02);
  assert.equal(closing.sandboxAtBaseline, false);
  assert.equal(lockFiles(s).length, 1);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.stoppedAt, "final-list-again");
  assert.equal(meta.status, "THROWN");
});

test("a connection lost during cleanup is needs-recovery with the lock kept", async () => {
  const probe = setup();
  await probeRun(probe.deps, FAST);
  const total = probe.fake.calls.length;
  const s = setup({ failAt: total - 2 });
  await assert.rejects(probeRun(s.deps, FAST), (error) => error.afterStart === true);
  assert.equal(s.ledgerRows.at(-1).event, "needs-recovery");
  assert.equal(lockFiles(s).length, 1);
  assert.match(s.privateFiles.meta.at(-1).stoppedAt, /^(cleanup|final)/);
});

test("the packet's limits must be the kit's: probe-v2's packet does not run probe-v3, and the reverse", async () => {
  const v2 = { ...packet, maxRequests: 17, reserveUsd: 0.05 };
  await assert.rejects(probeRun(setup({}, { packet: v2 }).deps, FAST), /limit/);
  await assert.rejects(probeRun(setup().deps, PROBE_V2_KIT), /limit/);
  const s = setup();
  s.deps.packet = { ...packet, reserveUsd: 1 };
  await assert.rejects(probeRun(s.deps, FAST), /limit/);
});

test("the kit is the only difference: the admission refuses a dirty tree, a quiet interval and a second run", async () => {
  const dirty = setup();
  dirty.deps.git = async () => ({ clean: false, commit: COMMIT });
  await assert.rejects(probeRun(dirty.deps, FAST), /clean/);
  const recent = `${JSON.stringify({ ts: "2026-10-02T08:45:00Z", event: "finished", outcome: "recorded", taskId: "STORAGE-OBJECT-SANDBOX", project: RECORD_PROJECT, packetSha256: "9".repeat(64), requests: 17, estimatedUsd: 0.01 })}\n`;
  await assert.rejects(probeRun(setup({}, { ledgerText: recent }).deps, FAST), /admission/);
  const ran = `${JSON.stringify({ ts: "2026-09-30T09:00:00Z", event: "finished", outcome: "recorded", taskId: "STORAGE-OBJECT-SANDBOX", project: RECORD_PROJECT, packetSha256: packet.packetSha256, requests: 40, estimatedUsd: 0.02 })}\n`;
  await assert.rejects(probeRun(setup({}, { ledgerText: ran }).deps, FAST), /already run/);
});

test("no file of the private run holds the owner token", async () => {
  const s = setup();
  await probeRun(s.deps, FAST);
  assert.ok(!JSON.stringify([s.privateFiles, s.ledgerRows]).includes(TOKEN));
});

test("the two kits name their commands and their limits", () => {
  assert.equal(PROBE_V2_KIT.command, "probe-production");
  assert.equal(PROBE_V3_KIT.command, "probe3-production");
  assert.equal(PROBE_V3_KIT.name, "probe-v3");
  assert.equal(PROBE_V2_KIT.name, "probe-v2");
  assert.equal(PROBE_V2_KIT.maxRequests, 17);
  assert.equal(PROBE_V3_KIT.maxRequests, 60);
  assert.equal(PROBE_V3_KIT.reserveUsd, 0.05);
  assert.equal(PROBE_V3_KIT.estimateUsd, 0.02);
});

test("the shipped kit spaces the writes to one object by a second, and leaves reads alone", async () => {
  const plan = PROBE_V3_KIT.buildPlan({
    projectId: RECORD_PROJECT,
    bucket: "fireemu-oracle-query.firebasestorage.app",
    runId: RUN,
    otherRunId: OTHER,
  });
  const pacer = PROBE_V3_KIT.pacer(plan);
  const name = plan.objects[0];
  const times = [];
  const attempt = async () => times.push(Date.now());
  await pacer.dispatch(name, attempt);
  await pacer.dispatch(name, attempt);
  assert.ok(times[1] - times[0] >= 900, `${times[1] - times[0]} ms between two writes`);
  // probe-v2 writes nothing to any object, so its pacer never waits.
  const quick = PROBE_V2_KIT.pacer(plan);
  const start = Date.now();
  await quick.dispatch(name, attempt);
  await quick.dispatch(name, attempt);
  assert.ok(Date.now() - start < 300);
});

test("the writes of a run go through the kit's pacer, built for that run's plan", async () => {
  const names = [];
  let seen;
  const kit = {
    ...PROBE_V3_KIT,
    pacer: (plan) => {
      seen = plan;
      return {
        dispatch: (name, attempt) => {
          names.push(name);
          return attempt();
        },
      };
    },
  };
  const s = setup();
  await probeRun(s.deps, kit);
  assert.equal(seen.prefix, `storage-object/${RUN}/`);
  // Only writes are paced, and each is named by the object it writes.
  assert.ok(names.length >= 10);
  for (const name of names) assert.ok(seen.objects.includes(name), name);
});

test("the shipped pacer accepts any name under the run's prefix, not only under the probe's own", async () => {
  const plan = PROBE_V3_KIT.buildPlan({
    projectId: RECORD_PROJECT,
    bucket: "fireemu-oracle-query.firebasestorage.app",
    runId: RUN,
    otherRunId: OTHER,
  });
  const pacer = PROBE_V3_KIT.pacer(plan);
  let ran = false;
  await pacer.dispatch(`${plan.prefix}elsewhere.bin`, async () => {
    ran = true;
  });
  assert.equal(ran, true);
});
