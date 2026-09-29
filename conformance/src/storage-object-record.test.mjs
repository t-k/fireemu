// The lean recorder: one recording per run. Every collaborator is a fake, so these tests send
// nothing. They fix the order (checks, then the lock, then the started row, then the requests,
// then one closing row), what each terminal state writes, and what keeps the project lock.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createRulesReader,
  createTokenProvider,
  RECORD_BUCKET,
  RECORD_PROJECT,
  recordRun,
  refuseUnsafeEnvironment,
  runnerDigest,
} from "./storage-object/record.mjs";
import { admissionProblems } from "./auth-fs-cross/sandbox.mjs";
import {
  encodeRow,
  needsRecoveryRow,
  startedRow,
  finishedRow,
} from "./storage-object/ledger-rows.mjs";

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
  packetName: "lean-v1",
  projectId: RECORD_PROJECT,
  maxRequests: 6000,
  reserveUsd: 1,
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
const approvalText = `- 2026-09-30 | STORAGE-OBJECT lean-v1 | decision=APPROVE; ${PINS.map((key) => `${key}=${packet[key]}`).join("; ")} | オーナー（ローカル試験） | packet.md\n`;
const NOW = Date.parse("2026-10-01T09:00:00Z");
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";

function setup(overrides = {}) {
  const base = mkdtempSync(join(tmpdir(), "storage-object-record-"));
  const lockDir = join(base, "sandbox-locks");
  const legacy = join(base, "sandbox-ledger.jsonl.lock");
  const events = [];
  const fetchCalls = [];
  const ledgerRows = [];
  let ledgerText = overrides.ledgerText ?? "";
  const privateFiles = { captures: [], events: [], meta: [] };
  const deps = {
    ids: { runId: RUN, otherRunId: OTHER },
    recording: 1,
    packet,
    review,
    ownerDecisionsText: approvalText,
    env: overrides.env ?? {},
    nodeVersion: "v24.14.0",
    ledger: {
      read: async () => {
        events.push("ledger-read");
        return ledgerText;
      },
      append: async (row) => {
        events.push(`ledger-append:${row.event}${row.outcome ? `:${row.outcome}` : ""}`);
        if (overrides.appendFails?.(row)) throw new Error("ledger writer failed");
        ledgerRows.push(row);
        ledgerText += encodeRow(row);
      },
    },
    git: async () => {
      events.push("git");
      return overrides.git ?? { clean: true, commit: COMMIT };
    },
    admission: admissionProblems,
    locks: { lockDir, legacyLockPath: legacy, pid: process.pid },
    privateRun: async (runId) => {
      events.push(`private-run:${runId}`);
      return {
        dir: join(base, "private", runId),
        capture: async (record) => privateFiles.captures.push(record),
        event: async (event) => privateFiles.events.push(event),
        meta: async (value) => privateFiles.meta.push(value),
      };
    },
    getToken: async () => "ya29.synthetic-owner-access-token-value",
    apiKey: "AIzaSyD-synthetic-web-api-key-value-000000",
    actualPins: Object.fromEntries(
      ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"].map((key) => [
        key,
        packet[key],
      ]),
    ),
    fetch:
      overrides.fetch ??
      (async (url, init) => {
        events.push("fetch");
        fetchCalls.push({
          url: String(url),
          headers: new Headers(init?.headers),
          method: init?.method,
        });
        if (String(url).includes("/releases/"))
          return Response.json({
            rulesetName: `projects/${RECORD_PROJECT}/rulesets/abc`,
            createTime: "t1",
            updateTime: "t2",
          });
        if (String(url).includes("/rulesets/"))
          return Response.json({
            source: { files: [{ name: "storage.rules", content: "fixed rules text" }] },
          });
        return new Response("{}");
      }),
    replay:
      overrides.replay ??
      (async (options) => {
        events.push("replay");
        const wire = options.wireFactory({
          origins: [options.storageOrigin, options.authOrigin, options.localControl.origin],
          limits: options.plan,
          captureDirectory: options.captureDirectory,
          onByteReserve: async () => {},
        });
        overrides.onWire?.(wire, options);
        return {
          status: "LOCAL_COMPLETE",
          wire: wire.snapshot(),
          counter: { total: 3000 },
          results: [],
          unresolved: [],
          cleanupFailures: [],
        };
      }),
    now: () => new Date(NOW),
    ...overrides.deps,
  };
  return { deps, events, ledgerRows, privateFiles, lockDir, legacy, base, fetchCalls };
}

const lockFiles = (s) => (existsSync(s.lockDir) ? readdirSync(s.lockDir) : []);

// ---- order and rows ------------------------------------------------------------------------------

test("a clean run checks, locks, writes started, sends, writes one closing row and releases the lock", async () => {
  const s = setup();
  const result = await recordRun(s.deps);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(
    s.events.filter((e) => !e.startsWith("fetch")),
    [
      "git",
      "ledger-read",
      `private-run:${RUN}`,
      "ledger-append:started",
      "replay",
      "ledger-append:finished:recorded",
    ],
  );
  assert.deepEqual(lockFiles(s), [], "the lock is released once the closing row is durable");
  const [started, closing] = s.ledgerRows;
  assert.equal(started.maxRequests, 3000);
  assert.equal(started.estimatedUsd, 0.5);
  assert.equal(started.project, RECORD_PROJECT);
  assert.equal(started.runId, RUN);
  assert.equal(started.packetSha256, packet.packetSha256);
  assert.equal(closing.sandboxAtBaseline, true);
  assert.equal(closing.runId, RUN);
});

test("the closing row counts what was really sent", async () => {
  const s = setup({
    replay: async (options) => {
      const wire = options.wireFactory({
        origins: [options.storageOrigin, options.authOrigin, options.localControl.origin],
        limits: options.plan,
        captureDirectory: options.captureDirectory,
        onByteReserve: async () => {},
      });
      await wire
        .fetch(`${options.localControl.origin}/v1/storage/rules`, { method: "GET", headers: {} })
        .catch(() => {});
      return {
        status: "LOCAL_COMPLETE",
        wire: { ...wire.snapshot(), realRequests: 2222 },
        counter: { total: 2100 },
        results: [],
        unresolved: [],
        cleanupFailures: [],
      };
    },
  });
  await recordRun(s.deps);
  assert.equal(s.ledgerRows.at(-1).requests, 2222);
  assert.equal(s.ledgerRows.at(-1).estimatedUsd, Number(((2222 / 3000) * 0.15).toFixed(6)));
});

test("the aggregate runs one recording with this run's plan and the placeholder credentials", async () => {
  let seen;
  const s = setup({ onWire: (wire, options) => (seen = options) });
  await recordRun(s.deps);
  assert.equal(seen.recordings, 1);
  assert.equal(seen.plan.projectId, RECORD_PROJECT);
  assert.equal(seen.plan.bucket, RECORD_BUCKET);
  assert.equal(seen.plan.recordings[0].runId, RUN);
  assert.equal(seen.plan.recordings[1].runId, OTHER);
  assert.equal(seen.credentials.admin, "Bearer owner");
  assert.equal(seen.localAuth.apiKey, "storage-object-local-key");
  assert.match(seen.localAuth.password, /^[A-Za-z0-9_-]{20,}$/);
  for (const origin of [seen.storageOrigin, seen.authOrigin, seen.localControl.origin]) {
    assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  }
});

test("a stopped run that cleaned up writes stopped-clean and releases the lock", async () => {
  const s = setup({
    replay: async () => ({
      status: "LOCAL_BLOCKED",
      wire: { attempts: 5, realRequests: 5 },
      counter: { total: 5 },
      results: [],
      unresolved: [],
      cleanupFailures: [],
    }),
  });
  const result = await recordRun(s.deps);
  assert.equal(result.outcome, "stopped-clean");
  assert.equal(s.ledgerRows.at(-1).outcome, "stopped-clean");
  assert.deepEqual(lockFiles(s), []);
});

test("a run that may have left objects writes needs-recovery and keeps the lock", async () => {
  const s = setup({
    replay: async () => ({
      status: "LOCAL_NEEDS_RECOVERY",
      wire: { attempts: 7, realRequests: 7 },
      counter: { total: 7 },
      results: [],
      unresolved: [{ name: "x" }],
      cleanupFailures: [],
    }),
  });
  const result = await recordRun(s.deps);
  assert.equal(result.outcome, "needs-recovery");
  const closing = s.ledgerRows.at(-1);
  assert.equal(closing.event, "needs-recovery");
  assert.equal(closing.outcome, "needs-recovery");
  assert.equal(closing.sandboxAtBaseline, false);
  assert.equal(lockFiles(s).length, 1, "the project lock stays until a recovery run");
});

test("an unknown aggregate status is treated as needs-recovery", async () => {
  const s = setup({
    replay: async () => ({ status: "SOMETHING_ELSE", wire: { attempts: 1, realRequests: 1 } }),
  });
  const result = await recordRun(s.deps);
  assert.equal(result.outcome, "needs-recovery");
  assert.equal(lockFiles(s).length, 1);
});

test("an aggregate that throws leaves needs-recovery and the lock, and the error reaches the caller", async () => {
  const s = setup({
    replay: async () => {
      throw new Error("aggregate exploded");
    },
  });
  await assert.rejects(recordRun(s.deps), /aggregate exploded/);
  assert.equal(s.ledgerRows.at(-1).event, "needs-recovery");
  assert.equal(lockFiles(s).length, 1);
});

test("a started row that cannot be written stops before any request and keeps the lock", async () => {
  const s = setup({ appendFails: (row) => row.event === "started" });
  await assert.rejects(recordRun(s.deps), /ledger writer failed/);
  assert.equal(s.events.includes("replay"), false);
  assert.equal(s.events.includes("fetch"), false);
  assert.equal(lockFiles(s).length, 1);
});

test("a closing row that cannot be written keeps the lock and reports the failure", async () => {
  const s = setup({ appendFails: (row) => row.event === "finished" });
  await assert.rejects(recordRun(s.deps), /ledger writer failed/);
  assert.equal(lockFiles(s).length, 1);
});

// ---- refusals before anything is written or sent ------------------------------------------------------

async function refused(s, pattern) {
  await assert.rejects(recordRun(s.deps), pattern);
  assert.equal(s.ledgerRows.length, 0, "no ledger row");
  assert.equal(s.events.includes("replay"), false, "no run");
  assert.equal(s.events.includes("fetch"), false, "no request");
  assert.deepEqual(lockFiles(s), [], "no lock left behind");
}

for (const [label, env] of [
  ["NODE_OPTIONS", { NODE_OPTIONS: "--require x" }],
  ["HTTPS_PROXY", { HTTPS_PROXY: "http://proxy:3128" }],
  ["https_proxy", { https_proxy: "http://proxy:3128" }],
  ["HTTP_PROXY", { HTTP_PROXY: "http://proxy:3128" }],
  ["http_proxy", { http_proxy: "http://proxy:3128" }],
  ["all_proxy", { all_proxy: "socks5://proxy:1080" }],
  ["SSL_CERT_DIR", { SSL_CERT_DIR: "/tmp/certs" }],
  ["ALL_PROXY", { ALL_PROXY: "socks5://proxy:1080" }],
  ["NODE_EXTRA_CA_CERTS", { NODE_EXTRA_CA_CERTS: "/tmp/ca.pem" }],
  ["SSL_CERT_FILE", { SSL_CERT_FILE: "/tmp/ca.pem" }],
  ["NODE_TLS_REJECT_UNAUTHORIZED", { NODE_TLS_REJECT_UNAUTHORIZED: "0" }],
  ["a storage emulator host", { STORAGE_EMULATOR_HOST: "127.0.0.1:9199" }],
  ["a Firebase Storage emulator host", { FIREBASE_STORAGE_EMULATOR_HOST: "127.0.0.1:9199" }],
  ["an Auth emulator host", { FIREBASE_AUTH_EMULATOR_HOST: "127.0.0.1:9099" }],
]) {
  test(`refuses a run with ${label} set`, async () => {
    const s = setup({ env });
    await refused(s, /environment/);
  });
}

test("refuses another Node version", async () => {
  const s = setup();
  s.deps.nodeVersion = "v22.22.1";
  await refused(s, /Node/);
});

test("refuses a dirty tree", async () => {
  const s = setup({ git: { clean: false, commit: COMMIT } });
  await refused(s, /clean/);
});

test("refuses a commit other than the approved one", async () => {
  const s = setup({ git: { clean: true, commit: "c".repeat(40) } });
  await refused(s, /commit/);
});

test("refuses without a matching approval", async () => {
  const s = setup();
  s.deps.ownerDecisionsText = "";
  await refused(s, /approval/);
});

test("refuses a revoked approval", async () => {
  const s = setup();
  s.deps.ownerDecisionsText = `${approvalText}- 2026-09-30 | STORAGE-OBJECT lean-v1 | REVOKED packetSha256=${packet.packetSha256} | オーナー（ローカル試験） | x\n`;
  await refused(s, /revoked/);
});

test("refuses a review that is not a clean approval", async () => {
  const s = setup();
  s.deps.review = { ...review, verdict: "APPROVE WITH CONDITIONS" };
  await refused(s, /review/);
});

test("refuses while another lane has an open run on the project", async () => {
  const other = `${JSON.stringify({ ts: "2026-09-28T04:00:00Z", event: "started", taskId: "FS-QUERY-INDEX-SANDBOX", project: RECORD_PROJECT, estimatedUsd: 1 })}\n`;
  const s = setup({ ledgerText: other });
  await refused(s, /admission/);
});

test("refuses within the quiet interval after another lane's line", async () => {
  const recent = `${JSON.stringify({ ts: "2026-10-01T08:45:00Z", event: "finished", outcome: "recorded", taskId: "FS-QUERY-INDEX-SANDBOX", project: RECORD_PROJECT, requests: 1, estimatedUsd: 0 })}\n`;
  const s = setup({ ledgerText: recent });
  await refused(s, /admission/);
});

test("refuses while this task's own earlier run is open or needs recovery", async () => {
  const ids = {
    runId: "aaaaaaaaaaaaaaaaaaaa",
    packetId: "lean-v1",
    packetSha256: packet.packetSha256,
    gitSha: COMMIT,
    corpusDigest: "c".repeat(64),
  };
  const open = encodeRow(
    startedRow({ ...ids, ts: "2026-09-30T09:00:00Z", maxRequests: 3000, estimatedUsd: 0.5 }),
  );
  await refused(setup({ ledgerText: open }), /admission/);
  const recovering =
    open +
    encodeRow(
      needsRecoveryRow({ ...ids, ts: "2026-09-30T10:00:00Z", requests: 10, estimatedUsd: 0.1 }),
    );
  await refused(setup({ ledgerText: recovering }), /admission/);
});

test("refuses while the legacy shared lock exists", async () => {
  const s = setup();
  writeFileSync(s.legacy, "held");
  await assert.rejects(recordRun(s.deps), /legacy shared lock/);
  assert.equal(s.ledgerRows.length, 0);
  assert.equal(s.events.includes("replay"), false);
});

test("refuses while another run holds the project lock", async () => {
  const s = setup();
  await recordRun(setup().deps).catch(() => {});
  const holder = setup();
  await import("node:fs/promises").then(({ mkdir, writeFile }) =>
    mkdir(holder.lockDir, { recursive: true, mode: 0o700 }).then(() =>
      writeFile(join(holder.lockDir, `${RECORD_PROJECT}.lock`), "held", { mode: 0o600 }),
    ),
  );
  await assert.rejects(recordRun(holder.deps), /project lock exists/);
  assert.equal(holder.ledgerRows.length, 0);
  assert.ok(s);
});

test("a third run of one packet is refused, and a second needs the first recorded", async () => {
  const ids = {
    runId: "aaaaaaaaaaaaaaaaaaaa",
    packetId: "lean-v1",
    packetSha256: packet.packetSha256,
    gitSha: COMMIT,
    corpusDigest: "c".repeat(64),
  };
  const closed = (runId, at) =>
    encodeRow(startedRow({ ...ids, runId, ts: at, maxRequests: 3000, estimatedUsd: 0.5 })) +
    encodeRow(
      finishedRow({
        ...ids,
        runId,
        ts: at.replace("T09", "T10"),
        outcome: "recorded",
        requests: 2000,
        estimatedUsd: 0.15,
      }),
    );
  const twice =
    closed("aaaaaaaaaaaaaaaaaaaa", "2026-09-29T09:00:00Z") +
    closed("bbbbbbbbbbbbbbbbbbbb", "2026-09-29T15:00:00Z");
  await refused(setup({ ledgerText: twice }), /already/);
  const stopped =
    encodeRow(
      startedRow({ ...ids, ts: "2026-09-29T09:00:00Z", maxRequests: 3000, estimatedUsd: 0.5 }),
    ) +
    encodeRow(
      finishedRow({
        ...ids,
        ts: "2026-09-29T10:00:00Z",
        outcome: "stopped-clean",
        requests: 40,
        estimatedUsd: 0.01,
      }),
    );
  // A stopped run recorded nothing, so a run of the same packet is a first recording again.
  const s = setup({ ledgerText: stopped });
  const result = await recordRun(s.deps);
  assert.equal(result.outcome, "recorded");
  // The second recording must follow a recorded first one.
  const s2 = setup({ ledgerText: stopped });
  s2.deps.recording = 2;
  await refused(s2, /first recording/);
  const first = closed("aaaaaaaaaaaaaaaaaaaa", "2026-09-29T09:00:00Z");
  const s3 = setup({ ledgerText: first });
  s3.deps.recording = 2;
  const second = await recordRun(s3.deps);
  assert.equal(second.outcome, "recorded");
});

test("a run ID that is not 20 hex characters is refused", async () => {
  const s = setup();
  s.deps.ids = { runId: "nothex", otherRunId: OTHER };
  await refused(s, /run ID/);
});

test("a packet whose pin differs from the code that would run is refused", async () => {
  for (const key of ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"]) {
    const s = setup();
    s.deps.actualPins = { ...s.deps.actualPins, [key]: "9".repeat(64) };
    await refused(s, new RegExp(`pin mismatch: ${key}`));
  }
  const missing = setup();
  missing.deps.actualPins = undefined;
  await refused(missing, /pin mismatch/);
});

test("recording and run IDs are checked one by one", async () => {
  for (const [change, pattern] of [
    [{ recording: 3 }, /recording must be 1 or 2/],
    [{ recording: 0 }, /recording must be 1 or 2/],
    [{ ids: { runId: "nothex", otherRunId: OTHER } }, /^Error: invalid run ID$/],
    [{ ids: { runId: RUN, otherRunId: "nothex" } }, /^Error: invalid run ID$/],
    [{ ids: { runId: RUN, otherRunId: RUN } }, /^Error: invalid run ID$/],
    [{ ids: { runId: "0123456789ABCDEF0123", otherRunId: OTHER } }, /^Error: invalid run ID$/],
    [{ ids: { runId: `${RUN}0`, otherRunId: OTHER } }, /^Error: invalid run ID$/],
    [{ ids: { runId: RUN.slice(0, 19), otherRunId: OTHER } }, /^Error: invalid run ID$/],
    [{ ids: { runId: RUN, otherRunId: OTHER.slice(1) } }, /^Error: invalid run ID$/],
  ]) {
    const s = setup();
    Object.assign(s.deps, change);
    await assert.rejects(
      recordRun(s.deps),
      (error) => pattern.test(String(error)),
      JSON.stringify(change),
    );
    assert.equal(s.ledgerRows.length, 0);
  }
});

test("the recorder targets the query project's default bucket", () => {
  assert.equal(RECORD_PROJECT, "fireemu-oracle-query");
  assert.equal(RECORD_BUCKET, "fireemu-oracle-query.firebasestorage.app");
});

test("every row of a run carries the run's identity", async () => {
  const s = setup();
  await recordRun(s.deps);
  assert.equal(s.ledgerRows.length, 2);
  for (const row of s.ledgerRows) {
    assert.equal(row.ts, new Date(NOW).toISOString());
    assert.equal(row.taskId, "STORAGE-OBJECT-SANDBOX");
    assert.equal(row.packetId, "lean-v1");
    assert.equal(row.packetSha256, packet.packetSha256);
    assert.equal(row.gitSha, COMMIT);
    assert.equal(row.corpusDigest, packet.corpusSha256);
    assert.equal(row.runId, RUN);
  }
});

test("the private directory, and a fresh password, reach the aggregate", async () => {
  const seen = [];
  for (let i = 0; i < 2; i++) {
    const s = setup({ onWire: (_wire, options) => seen.push(options) });
    await recordRun(s.deps);
    assert.equal(seen[i].captureDirectory, join(s.base, "private", RUN));
  }
  assert.notEqual(seen[0].localAuth.password, seen[1].localAuth.password);
});

test("the wire the recorder builds reaches this run's bucket, prefix and credentials", async () => {
  let prefix;
  const s = setup({
    replay: async (options) => {
      const wire = options.wireFactory({
        origins: [options.storageOrigin, options.authOrigin, options.localControl.origin],
        limits: options.plan,
        captureDirectory: options.captureDirectory,
        onByteReserve: async () => {},
      });
      prefix = options.plan.recordings[0].prefix;
      const owned = encodeURIComponent(`${prefix}a`);
      await wire.fetch(`${options.storageOrigin}/v0/b/${RECORD_BUCKET}/o/${owned}`, {
        method: "GET",
        headers: { authorization: "Bearer owner" },
      });
      await assert.rejects(
        wire.fetch(
          `${options.storageOrigin}/v0/b/${RECORD_BUCKET}/o/${encodeURIComponent("storage-object/zzzzzzzz/a")}`,
          {
            method: "GET",
            headers: { authorization: "Bearer owner" },
          },
        ),
      );
      await assert.rejects(
        wire.fetch(`${options.storageOrigin}/v0/b/other.appspot.com/o/${owned}`, {
          method: "GET",
          headers: {},
        }),
      );
      await wire.fetch(
        `${options.authOrigin}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=storage-object-local-key`,
        {
          method: "POST",
          headers: {},
          body: "{}",
        },
      );
      const rules = await (
        await wire.fetch(`${options.localControl.origin}/v1/storage/rules`, {
          method: "GET",
          headers: {},
        })
      ).json();
      assert.equal(rules.source, "fixed rules text");
      return {
        status: "LOCAL_COMPLETE",
        wire: wire.snapshot(),
        counter: { total: 4 },
        results: [],
        unresolved: [],
        cleanupFailures: [],
      };
    },
  });
  await recordRun(s.deps);
  const sent = s.fetchCalls.filter((call) => !call.url.includes("firebaserules"));
  assert.equal(sent.length, 2);
  assert.equal(new URL(sent[0].url).origin, "https://firebasestorage.googleapis.com");
  assert.equal(
    sent[0].headers.get("authorization"),
    "Bearer ya29.synthetic-owner-access-token-value",
  );
  assert.equal(sent[0].headers.get("x-goog-user-project"), RECORD_PROJECT);
  assert.equal(new URL(sent[1].url).origin, "https://identitytoolkit.googleapis.com");
  assert.equal(
    new URL(sent[1].url).searchParams.get("key"),
    "AIzaSyD-synthetic-web-api-key-value-000000",
  );
  const rulesReads = s.fetchCalls.filter((call) => call.url.includes("firebaserules"));
  assert.equal(rulesReads.length, 2);
  assert.equal(
    rulesReads[0].headers.get("authorization"),
    "Bearer ya29.synthetic-owner-access-token-value",
  );
  assert.ok(
    s.privateFiles.captures.some(
      (entry) => entry.kind === "rules-read" && entry.url.includes("/releases/"),
    ),
  );
  assert.ok(
    s.privateFiles.captures.some((entry) =>
      entry.request?.url.includes(prefix.replaceAll("/", "%2F")),
    ),
  );
  assert.equal(
    s.ledgerRows.at(-1).requests,
    4,
    "two sent requests and the two reads behind the Rules answer",
  );
});

test("what the aggregate journals reaches the private run with its kind", async () => {
  const s = setup({
    replay: async (options) => {
      await options.onStart({ x: 1 });
      await options.onReserve({ x: 2 });
      await options.onRecipeBegin({ x: 3 });
      await options.onRecipeFinish({ x: 4 });
      await options.onCapture({ x: 5 });
      await options.onJournal({ type: "aggregate-recipe-result", x: 6 });
      return {
        status: "LOCAL_COMPLETE",
        wire: { realRequests: 0 },
        unresolved: [],
        cleanupFailures: [],
      };
    },
  });
  await recordRun(s.deps);
  assert.deepEqual(s.privateFiles.events, [
    { type: "started", x: 1 },
    { type: "reserved", x: 2 },
    { type: "recipe-begin", x: 3 },
    { type: "recipe-finish", x: 4 },
    { type: "response", x: 5 },
    { type: "aggregate-recipe-result", x: 6 },
  ]);
});

test("a stopped run with unresolved objects or failed cleanup is never clean", async () => {
  for (const status of ["LOCAL_COMPLETE", "LOCAL_BLOCKED"]) {
    for (const extra of [{ unresolved: [{ name: "x" }] }, { cleanupFailures: [{ reason: "x" }] }]) {
      const s = setup({
        replay: async () => ({
          status,
          wire: { realRequests: 9 },
          unresolved: [],
          cleanupFailures: [],
          ...extra,
        }),
      });
      const result = await recordRun(s.deps);
      assert.equal(result.outcome, "needs-recovery", `${status} ${JSON.stringify(extra)}`);
      assert.equal(lockFiles(s).length, 1);
    }
  }
});

test("the private summary names the outcome, and the unresolved objects of a run that needs recovery", async () => {
  const ok = setup();
  await recordRun(ok.deps);
  assert.deepEqual(ok.privateFiles.meta, [
    {
      runId: RUN,
      recording: 1,
      outcome: "recorded",
      status: "LOCAL_COMPLETE",
      reason: null,
      requests: 0,
      plan: { runId: RUN, prefix: `storage-object/${RUN}/` },
    },
  ]);
  const bad = setup({
    replay: async () => ({
      status: "LOCAL_NEEDS_RECOVERY",
      reason: "Upload failed",
      wire: { realRequests: 7 },
      unresolved: [{ name: "x" }],
      cleanupFailures: [{ reason: "y" }],
    }),
  });
  await recordRun(bad.deps);
  assert.equal(bad.privateFiles.meta[0].reason, "Upload failed");
  assert.deepEqual(bad.privateFiles.meta[0].unresolved, [{ name: "x" }]);
  assert.deepEqual(bad.privateFiles.meta[0].cleanupFailures, [{ reason: "y" }]);
  assert.equal(bad.privateFiles.meta[0].requests, 7);
});

test("the private summary names the recording number", async () => {
  const first = setup();
  await recordRun(first.deps);
  assert.equal(first.privateFiles.meta[0].recording, 1);
  const second = setup({ ledgerText: closedRow() });
  second.deps.recording = 2;
  await recordRun(second.deps);
  assert.equal(second.privateFiles.meta[0].recording, 2);
});

test("a run that throws after sending records what was really sent", async () => {
  const s = setup({
    replay: async (options) => {
      const wire = options.wireFactory({
        origins: [options.storageOrigin, options.authOrigin, options.localControl.origin],
        limits: options.plan,
        captureDirectory: options.captureDirectory,
        onByteReserve: async () => {},
      });
      const owned = encodeURIComponent(`${options.plan.recordings[0].prefix}a`);
      for (let i = 0; i < 2; i++)
        await wire.fetch(`${options.storageOrigin}/v0/b/${RECORD_BUCKET}/o/${owned}`, {
          method: "GET",
          headers: {},
        });
      throw new Error("aggregate exploded");
    },
  });
  await assert.rejects(recordRun(s.deps), /aggregate exploded/);
  assert.equal(s.ledgerRows.at(-1).requests, 2);
});

test("a result without wire figures falls back on the wire's own count", async () => {
  const s = setup({
    replay: async (options) => {
      const wire = options.wireFactory({
        origins: [options.storageOrigin, options.authOrigin, options.localControl.origin],
        limits: options.plan,
        captureDirectory: options.captureDirectory,
        onByteReserve: async () => {},
      });
      const owned = encodeURIComponent(`${options.plan.recordings[0].prefix}a`);
      await wire.fetch(`${options.storageOrigin}/v0/b/${RECORD_BUCKET}/o/${owned}`, {
        method: "GET",
        headers: {},
      });
      return { status: "LOCAL_COMPLETE", unresolved: [], cleanupFailures: [] };
    },
  });
  await recordRun(s.deps);
  assert.equal(s.ledgerRows.at(-1).requests, 1);
});

// ---- what earlier runs of a packet mean ---------------------------------------------------------------------

const closedRow = (over = {}) =>
  `${JSON.stringify({
    ts: "2026-09-29T10:00:00Z",
    event: "finished",
    outcome: "recorded",
    taskId: "STORAGE-OBJECT-SANDBOX",
    project: RECORD_PROJECT,
    packetSha256: packet.packetSha256,
    requests: 100,
    estimatedUsd: 0.01,
    ...over,
  })}\n`;

test("only closing rows of this packet, this task and this project count", async () => {
  const other = [
    closedRow({ packetSha256: "0".repeat(64) }),
    closedRow({ taskId: "OTHER-SANDBOX" }),
    closedRow({ project: "fireemu-oracle-idp" }),
    closedRow({ event: "note" }),
  ].join("");
  // Two of each would be two recorded runs if any of them counted.
  const s = setup({ ledgerText: other + other });
  const result = await recordRun(s.deps);
  assert.equal(result.outcome, "recorded");
});

test("a line of the ledger that is not JSON is ignored by the packet history", async () => {
  const s = setup({
    ledgerText: `not json\n${closedRow({ requests: 10 })}`.replace("recorded", "stopped-clean"),
  });
  assert.equal((await recordRun(s.deps)).outcome, "recorded");
});

test("a first recording that is already recorded is refused for recording 1", async () => {
  const s = setup({ ledgerText: closedRow() });
  await refused(s, /first recording is already recorded/);
});

test("the request budget counts every closing row, a recovery row included", async () => {
  const start = (at) =>
    `${JSON.stringify({ ts: at, event: "started", taskId: "STORAGE-OBJECT-SANDBOX", project: RECORD_PROJECT, packetSha256: packet.packetSha256, maxRequests: 3000, estimatedUsd: 0.5 })}\n`;
  const rows =
    start("2026-09-28T09:00:00Z") +
    closedRow({ ts: "2026-09-28T10:00:00Z", outcome: "stopped-clean", requests: 1600 }) +
    start("2026-09-28T11:00:00Z") +
    closedRow({
      ts: "2026-09-28T12:00:00Z",
      event: "needs-recovery",
      outcome: "needs-recovery",
      requests: 1500,
    }) +
    closedRow({ ts: "2026-09-28T13:00:00Z", outcome: "recovered-no-observation", requests: 10 });
  await refused(setup({ ledgerText: rows }), /budget/);
});

test("the budget is exactly the packet's request limit", async () => {
  const exact = closedRow({ outcome: "stopped-clean", requests: 3000 });
  const s = setup({ ledgerText: exact });
  assert.equal((await recordRun(s.deps)).outcome, "recorded");
  const over = closedRow({ outcome: "stopped-clean", requests: 3001 });
  await refused(setup({ ledgerText: over }), /budget/);
});

test("a closing row without a request count is charged as a whole run", async () => {
  const noCount = () => closedRow({ outcome: "stopped-clean", requests: undefined });
  const one = setup({ ledgerText: noCount() });
  assert.equal((await recordRun(one.deps)).outcome, "recorded");
  await refused(setup({ ledgerText: noCount() + noCount() }), /budget/);
});

// ---- environment, digest ---------------------------------------------------------------------------------

test("refuseUnsafeEnvironment accepts a clean environment and names the offending variable", () => {
  assert.doesNotThrow(() => refuseUnsafeEnvironment({ PATH: "/bin", HOME: "/h" }, "v24.14.0"));
  assert.throws(() => refuseUnsafeEnvironment({ NODE_OPTIONS: "" }, "v24.14.0"), /NODE_OPTIONS/);
  assert.throws(() => refuseUnsafeEnvironment({}, "v24.13.0"), /Node/);
});

test("runnerDigest is stable and changes with any file or hash", () => {
  const files = [
    { file: "a.mjs", sha256: "1".repeat(64) },
    { file: "b.mjs", sha256: "2".repeat(64) },
  ];
  const base = runnerDigest(files);
  assert.match(base, /^[0-9a-f]{64}$/);
  assert.equal(runnerDigest(files), base);
  assert.notEqual(runnerDigest([files[0], { file: "b.mjs", sha256: "3".repeat(64) }]), base);
  assert.notEqual(runnerDigest([files[0], { file: "c.mjs", sha256: "2".repeat(64) }]), base);
  assert.notEqual(runnerDigest([files[0]]), base);
  assert.equal(runnerDigest([files[1], files[0]]), base, "the order of the list does not matter");
  assert.equal(
    runnerDigest([
      { ...files[0], size: 1 },
      { ...files[1], mtime: "x" },
    ]),
    base,
    "only the name and the hash count",
  );
});

// ---- the token provider -------------------------------------------------------------------------------------

test("the token is fetched once and reused until it is about to expire", async () => {
  let calls = 0;
  let clock = 0;
  const provider = createTokenProvider({
    run: async () => `ya29.token-number-${++calls}-0000000000`,
    now: () => clock,
    ttlMs: 40 * 60_000,
  });
  assert.equal(await provider(), "ya29.token-number-1-0000000000");
  clock = 39 * 60_000;
  assert.equal(await provider(), "ya29.token-number-1-0000000000");
  clock = 40 * 60_000;
  assert.equal(await provider(), "ya29.token-number-2-0000000000");
  assert.equal(calls, 2);
});

test("a token provider that cannot get a token throws a message without the command output", async () => {
  const provider = createTokenProvider({
    run: async () => {
      throw new Error("gcloud said ya29.leaked-token-value-0000000000");
    },
    now: () => 0,
  });
  await assert.rejects(
    provider(),
    (error) => /unavailable/.test(error.message) && !error.message.includes("ya29"),
  );
});

test("the token provider refuses an output that is not one token", async () => {
  for (const output of ["", "two words here 1234567890", "short", undefined, 42]) {
    const provider = createTokenProvider({ run: async () => output, now: () => 0 });
    await assert.rejects(provider(), /unavailable/);
  }
});

test("the token provider trims the trailing newline gcloud prints", async () => {
  const provider = createTokenProvider({
    run: async () => "ya29.synthetic-owner-access-token-value\n",
    now: () => 0,
  });
  assert.equal(await provider(), "ya29.synthetic-owner-access-token-value");
});

test("the token provider validates its configuration", () => {
  for (const change of [
    { run: undefined },
    { now: undefined },
    { ttlMs: 0 },
    { ttlMs: 3_600_001 },
  ]) {
    assert.throws(() => createTokenProvider({ run: async () => "x", now: () => 0, ...change }));
  }
});

// ---- the Rules reader ----------------------------------------------------------------------------------------

test("the Rules reader reads the bucket release and its ruleset with the owner token", async () => {
  const calls = [];
  const rulesetName = `projects/${RECORD_PROJECT}/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8`;
  const reader = createRulesReader({
    projectId: RECORD_PROJECT,
    bucket: RECORD_BUCKET,
    getToken: async () => "ya29.synthetic-owner-access-token-value",
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), headers: new Headers(init.headers), method: init.method });
      return String(url).includes("/releases/")
        ? Response.json({ name: "n", rulesetName, createTime: "t1", updateTime: "t2" })
        : Response.json({
            name: rulesetName,
            source: { files: [{ name: "storage.rules", content: "rules text" }] },
          });
    },
  });
  const result = await reader();
  assert.equal(result.source, "rules text");
  assert.equal(result.requests, 2);
  assert.equal(result.rulesetName, rulesetName);
  assert.equal(
    calls[0].url,
    `https://firebaserules.googleapis.com/v1/projects/${RECORD_PROJECT}/releases/firebase.storage/${RECORD_BUCKET}`,
  );
  assert.equal(calls[1].url, `https://firebaserules.googleapis.com/v1/${rulesetName}`);
  for (const call of calls) {
    assert.equal(call.method, "GET");
    assert.equal(
      call.headers.get("authorization"),
      "Bearer ya29.synthetic-owner-access-token-value",
    );
    assert.equal(call.headers.get("x-goog-user-project"), RECORD_PROJECT);
  }
});

test("the Rules reader refuses each malformed answer, with its own message", async () => {
  const good = `projects/${RECORD_PROJECT}/rulesets/abc`;
  const goodRuleset = () => Response.json({ source: { files: [{ content: "text" }] } });
  const make = (release, ruleset) =>
    createRulesReader({
      projectId: RECORD_PROJECT,
      bucket: RECORD_BUCKET,
      getToken: async () => "ya29.synthetic-owner-access-token-value",
      fetchImpl: async (url) => (String(url).includes("/releases/") ? release() : ruleset()),
    });
  const release =
    (body = { rulesetName: good }, status = 200) =>
    () =>
      new Response(JSON.stringify(body), { status });
  const ruleset =
    (body, status = 200) =>
    () =>
      new Response(JSON.stringify(body), { status });
  const cases = [
    [
      make(release({ rulesetName: "projects/other/rulesets/abc" }), goodRuleset),
      /names no ruleset of this project/,
    ],
    [make(release({ rulesetName: 42 }), goodRuleset), /names no ruleset of this project/],
    [make(release({}), goodRuleset), /names no ruleset of this project/],
    [make(release(), ruleset({ source: { files: [] } })), /not one source file/],
    [make(release(), ruleset({ source: { files: {} } })), /not one source file/],
    [
      make(release(), ruleset({ source: { files: [{ content: "a" }, { content: "b" }] } })),
      /not one source file/,
    ],
    [make(release(), ruleset({ source: { files: [{ content: 5 }] } })), /not one source file/],
    [make(release(), ruleset({})), /not one source file/],
    [make(release(undefined, 404), goodRuleset), /Rules read failed/],
    [make(release(), ruleset({ source: { files: [{ content: "a" }] } }, 500)), /Rules read failed/],
    [make(() => new Response("not json", { status: 200 }), goodRuleset), /Rules read failed/],
  ];
  for (const [reader, pattern] of cases) await assert.rejects(reader(), pattern);
});

test("the Rules reader records each read without the body", async () => {
  const records = [];
  const good = `projects/${RECORD_PROJECT}/rulesets/abc`;
  const reader = createRulesReader({
    projectId: RECORD_PROJECT,
    bucket: RECORD_BUCKET,
    getToken: async () => "ya29.synthetic-owner-access-token-value",
    record: async (entry) => records.push(entry),
    fetchImpl: async (url) =>
      String(url).includes("/releases/")
        ? Response.json({ rulesetName: good })
        : Response.json({ source: { files: [{ content: "text" }] } }),
  });
  await reader();
  assert.equal(records.length, 2);
  assert.deepEqual(
    records.map((entry) => entry.kind),
    ["rules-read", "rules-read"],
  );
  assert.deepEqual(
    records.map((entry) => entry.status),
    [200, 200],
  );
  assert.ok(records.every((entry) => /^[0-9a-f]{64}$/.test(entry.bodySha256)));
  assert.equal(JSON.stringify(records).includes("text"), false);
});

test("the Rules reader validates its configuration", () => {
  const base = {
    projectId: RECORD_PROJECT,
    bucket: RECORD_BUCKET,
    getToken: async () => "t",
    fetchImpl: async () => new Response("{}"),
  };
  assert.doesNotThrow(() => createRulesReader(base));
  for (const change of [
    { projectId: 1 },
    { bucket: undefined },
    { getToken: undefined },
    { fetchImpl: undefined },
  ]) {
    assert.throws(() => createRulesReader({ ...base, ...change }));
  }
});
