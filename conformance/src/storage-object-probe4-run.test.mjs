// One run of probe-v4 through the shared probe runner: the rows, the closing row and what keeps the
// project lock, including a production that accepts what it should refuse. Every collaborator is a
// fake, and the production is the stateful fake of the probe-v4 tests, so nothing is sent.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { admissionProblems } from "./auth-fs-cross/sandbox.mjs";
import { production } from "./storage-object-probe4-fake.mjs";
import { encodeRow } from "./storage-object/ledger-rows.mjs";
import { PROBE_V4_KIT, probeRun } from "./storage-object/probe-run.mjs";
import { PROBE4_MAX_REQUESTS, PROBE4_RESERVE_USD } from "./storage-object/probe4.mjs";
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
  packetName: "probe-v4",
  projectId: RECORD_PROJECT,
  maxRequests: PROBE4_MAX_REQUESTS,
  reserveUsd: PROBE4_RESERVE_USD,
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
const approvalText = `- 2026-10-01 | STORAGE-OBJECT probe-v4 | decision=APPROVE; ${PINS.map((key) => `${key}=${packet[key]}`).join("; ")} | オーナー（ローカル試験） | packet.md\n`;
const NOW = Date.parse("2026-10-02T09:00:00Z");
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";
const TOKEN = "ya29.synthetic-owner-access-token-value";

function setup(productionOptions = {}, overrides = {}) {
  const base = mkdtempSync(join(tmpdir(), "storage-object-probe4-run-"));
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
  ...PROBE_V4_KIT,
  pacer: () => ({ dispatch: (_name, attempt) => attempt() }),
});

const lockFiles = (s) => (existsSync(s.lockDir) ? readdirSync(s.lockDir) : []);

test("an honest run: started, the refusals, removal, one closing row `recorded`, the lock released", async () => {
  const s = setup();
  const result = await probeRun(s.deps, FAST);
  assert.equal(result.outcome, "recorded");
  assert.equal(s.fake.store.size, 0);
  assert.equal(result.requests, s.fake.calls.length);
  assert.ok(result.requests <= 40, `${result.requests}`);
  assert.deepEqual(s.events, ["ledger-append:started", "ledger-append:finished:recorded"]);
  const [started, closing] = s.ledgerRows;
  assert.equal(started.maxRequests, 60);
  assert.equal(started.estimatedUsd, 0.02);
  assert.equal(closing.requests, result.requests);
  assert.deepEqual(lockFiles(s), []);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.status, "PROBE_COMPLETE");
  assert.equal(meta.interrupted, undefined);
  assert.equal(s.privateFiles.captures.length, result.requests);
});

test("a production that accepts every refused write still ends recorded, prefix empty, inside the request limit", async () => {
  const s = setup({ acceptRefused: true });
  const result = await probeRun(s.deps, FAST);
  assert.equal(result.outcome, "recorded");
  assert.equal(s.fake.store.size, 0);
  assert.ok(result.requests <= 60, `${result.requests}`);
  assert.deepEqual(lockFiles(s), []);
});

test("a connection lost during the recording stops clean when the prefix reads back empty", async () => {
  const s = setup({ failAt: 12 });
  const result = await probeRun(s.deps, FAST);
  assert.equal(result.outcome, "stopped-clean");
  assert.equal(s.fake.store.size, 0);
  assert.deepEqual(s.events, ["ledger-append:started", "ledger-append:finished:stopped-clean"]);
  assert.equal(s.privateFiles.meta.at(-1).interrupted.reason, "fetch failed");
  assert.deepEqual(lockFiles(s), []);
});

test("an object that cannot be removed writes needs-recovery and keeps the lock", async () => {
  const s = setup({ deleteFails: `storage-object/${RUN}/probe4/pre/target.bin` });
  await assert.rejects(probeRun(s.deps, FAST), (error) => error.afterStart === true);
  assert.equal(s.ledgerRows.at(-1).event, "needs-recovery");
  assert.equal(lockFiles(s).length, 1);
});

test("the shipped kit names its command, its limits and the paced writer", () => {
  assert.equal(PROBE_V4_KIT.command, "probe4-production");
  assert.equal(PROBE_V4_KIT.name, "probe-v4");
  assert.equal(PROBE_V4_KIT.maxRequests, 60);
  assert.equal(PROBE_V4_KIT.reserveUsd, 0.05);
  assert.equal(PROBE_V4_KIT.estimateUsd, 0.02);
  assert.equal(typeof PROBE_V4_KIT.pacer({ prefix: "storage-object/x/" }).dispatch, "function");
});

test("the shipped kit spaces the writes to one object by a second, and the run's writes go through the kit's pacer", async () => {
  const plan = PROBE_V4_KIT.buildPlan({
    projectId: RECORD_PROJECT,
    bucket: "fireemu-oracle-query.firebasestorage.app",
    runId: RUN,
    otherRunId: OTHER,
  });
  const pacer = PROBE_V4_KIT.pacer(plan);
  const times = [];
  const attempt = async () => times.push(Date.now());
  await pacer.dispatch(plan.objects[0], attempt);
  await pacer.dispatch(plan.objects[0], attempt);
  assert.ok(times[1] - times[0] >= 900, `${times[1] - times[0]} ms between two writes`);

  const names = [];
  let seen;
  const kit = {
    ...PROBE_V4_KIT,
    pacer: (built) => {
      seen = built;
      return {
        dispatch: (name, run) => {
          names.push(name);
          return run();
        },
      };
    },
  };
  await probeRun(setup().deps, kit);
  assert.equal(seen.prefix, `storage-object/${RUN}/`);
  assert.ok(names.length >= 10);
  for (const name of names) assert.ok(name.startsWith(seen.scope), name);
});
