// One run of the read-only probe. Every collaborator is a fake, so these tests send nothing. They
// fix the order (checks, then the lock, then the started row, then nine requests, then one closing
// row), what each end writes, and what keeps the project lock.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { admissionProblems } from "./auth-fs-cross/sandbox.mjs";
import {
  encodeRow,
  finishedRow,
  needsRecoveryRow,
  startedRow,
} from "./storage-object/ledger-rows.mjs";
import { probeRun } from "./storage-object/probe-run.mjs";
import { PROBE_MAX_REQUESTS, PROBE_RESERVE_USD } from "./storage-object/probe.mjs";
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
  packetName: "probe-v2",
  projectId: RECORD_PROJECT,
  maxRequests: PROBE_MAX_REQUESTS,
  reserveUsd: PROBE_RESERVE_USD,
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
const approvalText = `- 2026-10-01 | STORAGE-OBJECT probe-v2 | decision=APPROVE; ${PINS.map((key) => `${key}=${packet[key]}`).join("; ")} | オーナー（ローカル試験） | packet.md\n`;
const NOW = Date.parse("2026-10-02T09:00:00Z");
const RUN = "0123456789abcdef0123";
const OTHER = "fedcba9876543210fedc";
const TOKEN = "ya29.synthetic-owner-access-token-value";

function setup(overrides = {}) {
  const base = mkdtempSync(join(tmpdir(), "storage-object-probe-run-"));
  const lockDir = join(base, "sandbox-locks");
  const legacy = join(base, "sandbox-ledger.jsonl.lock");
  const events = [];
  const fetchCalls = [];
  const ledgerRows = [];
  let ledgerText = overrides.ledgerText ?? "";
  const privateFiles = { captures: [], events: [], meta: [] };
  const deps = {
    ids: { runId: RUN, otherRunId: OTHER },
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
    git: async () => overrides.git ?? { clean: true, commit: COMMIT },
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
    getToken: async () => TOKEN,
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
        if (isGcsList(url)) return emptyList();
        return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
      }),
    now: () => new Date(NOW),
    ...overrides.deps,
  };
  return { deps, events, ledgerRows, privateFiles, lockDir, legacy, fetchCalls };
}

/** A production that answers the GCS list of the probe's prefix with an empty one. */
const isGcsList = (url) => /\/storage\/v1\/b\/[^/]+\/o\?prefix=/.test(String(url));
const emptyList = () =>
  new Response('{"kind":"storage#objects"}', {
    status: 200,
    headers: { "content-type": "application/json" },
  });

const lockFiles = (s) => (existsSync(s.lockDir) ? readdirSync(s.lockDir) : []);

test("a clean run checks, locks, writes started, sends nine requests, writes one closing row, releases the lock", async () => {
  const s = setup();
  const result = await probeRun(s.deps);
  assert.equal(result.outcome, "recorded");
  assert.equal(result.requests, 11);
  assert.deepEqual(
    s.events.filter((e) => e !== "fetch"),
    [
      "ledger-read",
      "ledger-read",
      `private-run:${RUN}`,
      "ledger-append:started",
      "ledger-append:finished:recorded",
    ],
  );
  assert.equal(
    s.fetchCalls.length,
    11,
    "nine requests and two session starts that got no session URL",
  );
  assert.deepEqual(lockFiles(s), []);
  const [started, closing] = s.ledgerRows;
  assert.equal(started.maxRequests, 17);
  assert.equal(started.estimatedUsd, 0.01);
  assert.equal(started.project, RECORD_PROJECT);
  assert.equal(started.runId, RUN);
  assert.equal(started.packetId, "probe-v2");
  assert.equal(closing.requests, 11);
  assert.equal(closing.sandboxAtBaseline, true);
  assert.equal(closing.runId, RUN);
  assert.equal(closing.packetSha256, packet.packetSha256);
});

test("the started row comes before the first request, the identity request is first", async () => {
  const s = setup();
  await probeRun(s.deps);
  assert.ok(s.events.indexOf("ledger-append:started") < s.events.indexOf("fetch"));
  assert.equal(
    s.fetchCalls[0].url,
    `https://identitytoolkit.googleapis.com/v1/projects/${RECORD_PROJECT}/accounts:lookup`,
  );
  assert.equal(s.fetchCalls[0].method, "POST");
});

test("the owner token and the quota project go to the owner routes, and to no other", async () => {
  const s = setup();
  await probeRun(s.deps);
  const withToken = s.fetchCalls.filter(
    (c) => c.headers.get("authorization") === `Bearer ${TOKEN}`,
  );
  assert.equal(withToken.length, 9, "five owner reads, two session starts and two lists");
  for (const call of s.fetchCalls) {
    assert.equal(
      call.headers.get("x-goog-user-project"),
      call.headers.get("authorization") ? RECORD_PROJECT : null,
    );
  }
  assert.deepEqual(
    s.fetchCalls.slice(5, 7).map((c) => c.headers.get("authorization")),
    [null, null],
  );
});

test("every answer, whatever its status, is captured and the run is still recorded", async () => {
  const statuses = [403, 403, 404, 200, 401, 404, 500, 404, 500, 200, 404];
  let index = 0;
  const s = setup({
    fetch: async () => {
      const at = index++;
      // The tenth request is the GCS list: 200 with an empty prefix.
      return new Response(at === 9 ? "{}" : "x", {
        status: statuses[at],
        headers: { "content-type": at === 9 ? "application/json" : "text/plain" },
      });
    },
  });
  const result = await probeRun(s.deps);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(
    s.privateFiles.captures.map((record) => record.response.status),
    statuses,
  );
  assert.deepEqual(
    s.privateFiles.meta
      .at(-1)
      .answers.filter((row) => row.status !== undefined)
      .map((row) => row.status),
    statuses,
  );
  assert.equal(
    s.privateFiles.meta.at(-1).answers.filter((row) => row.skipped === "no session URL").length,
    6,
  );
});

test("a lost connection at the identity request sends nothing more, writes needs-recovery, keeps the lock", async () => {
  let calls = 0;
  const s = setup({
    fetch: async () => {
      calls++;
      throw new TypeError("fetch failed");
    },
  });
  await assert.rejects(probeRun(s.deps), (error) => {
    assert.equal(error.afterStart, true);
    return true;
  });
  assert.equal(calls, 1);
  const closing = s.ledgerRows.at(-1);
  assert.equal(closing.event, "needs-recovery");
  assert.equal(closing.outcome, "needs-recovery");
  assert.equal(closing.requests, 1);
  assert.equal(lockFiles(s).length, 1, "the project lock stays");
  assert.equal(s.privateFiles.meta.at(-1).stoppedAt, "identity-owner-lookup");
});

test("a lost connection part-way stops there, and the summary says how far it got", async () => {
  let calls = 0;
  const s = setup({
    fetch: async () => {
      if (++calls === 5) throw new TypeError("fetch failed");
      return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(probeRun(s.deps), /fetch failed/);
  assert.equal(calls, 5);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.outcome, "needs-recovery");
  assert.equal(meta.stoppedAt, "firebase-media-owner");
  assert.equal(meta.answered.length, 4);
  assert.equal(meta.requests, 5);
  assert.equal(s.ledgerRows.at(-1).requests, 5);
  assert.equal(lockFiles(s).length, 1);
});

test("a started row that cannot be written stops before any request and keeps the lock", async () => {
  const s = setup({ appendFails: (row) => row.event === "started" });
  await assert.rejects(probeRun(s.deps), /ledger writer failed/);
  assert.equal(s.fetchCalls.length, 0);
  assert.equal(lockFiles(s).length, 1);
});

test("a closing row that cannot be written keeps the lock and reports the failure", async () => {
  const s = setup({ appendFails: (row) => row.event === "finished" });
  await assert.rejects(probeRun(s.deps), (error) => error.afterStart === true);
  assert.equal(lockFiles(s).length, 1);
});

test("an error after the started row says a run had started, and a refusal before it does not", async () => {
  const s = setup({ appendFails: (row) => row.event === "started" });
  await assert.rejects(probeRun(s.deps), (error) => error.afterStart === true);
  const refusedRun = setup({ git: { clean: false, commit: COMMIT } });
  await assert.rejects(probeRun(refusedRun.deps), (error) => error.afterStart !== true);
});

// ---- refusals before anything is written or sent ------------------------------------------------------

async function refused(s, pattern) {
  await assert.rejects(probeRun(s.deps), pattern);
  assert.equal(s.ledgerRows.length, 0, "no ledger row");
  assert.equal(s.fetchCalls.length, 0, "no request");
  assert.deepEqual(lockFiles(s), [], "no lock left behind");
}

test("refuses an unsafe environment", async () => {
  await refused(setup({ env: { HTTPS_PROXY: "http://proxy:3128" } }), /environment/);
  await refused(setup({ env: { NODE_OPTIONS: "--require x" } }), /environment/);
});

test("refuses another Node version", async () => {
  const s = setup();
  s.deps.nodeVersion = "v22.22.1";
  await refused(s, /Node/);
});

test("refuses a dirty tree and a commit other than the approved one", async () => {
  await refused(setup({ git: { clean: false, commit: COMMIT } }), /clean/);
  await refused(setup({ git: { clean: true, commit: "c".repeat(40) } }), /commit/);
});

test("refuses without a matching approval, and after a revocation", async () => {
  const none = setup();
  none.deps.ownerDecisionsText = "";
  await refused(none, /approval/);
  const revoked = setup();
  revoked.deps.ownerDecisionsText = `${approvalText}- 2026-10-01 | STORAGE-OBJECT probe-v2 | REVOKED packetSha256=${packet.packetSha256} | オーナー（ローカル試験） | x\n`;
  await refused(revoked, /revoked/);
});

test("refuses a review that is not a clean approval", async () => {
  const s = setup();
  s.deps.review = { ...review, verdict: "APPROVE WITH CONDITIONS" };
  await refused(s, /review/);
});

test("refuses a packet whose limits are not the probe's", async () => {
  const s = setup();
  s.deps.packet = { ...packet, maxRequests: 10 };
  await refused(s, /limit/);
  const t = setup();
  t.deps.packet = { ...packet, reserveUsd: 1 };
  await refused(t, /limit/);
});

test("refuses a packet whose pin differs from the code that would run", async () => {
  for (const key of ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"]) {
    const s = setup();
    s.deps.actualPins = { ...s.deps.actualPins, [key]: "f".repeat(64) };
    await refused(s, new RegExp(`pin mismatch: ${key}`));
  }
});

test("refuses run IDs that are not two different 20-hex names", async () => {
  for (const ids of [
    { runId: "abc", otherRunId: OTHER },
    { runId: RUN, otherRunId: "abc" },
    { runId: RUN, otherRunId: RUN },
    undefined,
  ]) {
    const s = setup();
    s.deps.ids = ids;
    await refused(s, /run ID/);
  }
});

test("refuses while another lane has an open run, and within the quiet interval", async () => {
  const open = `${JSON.stringify({ ts: "2026-09-28T04:00:00Z", event: "started", taskId: "FS-QUERY-INDEX-SANDBOX", project: RECORD_PROJECT, estimatedUsd: 1 })}\n`;
  await refused(setup({ ledgerText: open }), /admission/);
  const recent = `${JSON.stringify({ ts: "2026-10-02T08:45:00Z", event: "finished", outcome: "recorded", taskId: "FS-QUERY-INDEX-SANDBOX", project: RECORD_PROJECT, requests: 1, estimatedUsd: 0 })}\n`;
  await refused(setup({ ledgerText: recent }), /admission/);
  const edge = `${JSON.stringify({ ts: "2026-10-02T08:30:00Z", event: "finished", outcome: "recorded", taskId: "FS-QUERY-INDEX-SANDBOX", project: RECORD_PROJECT, requests: 1, estimatedUsd: 0 })}\n`;
  const ok = setup({ ledgerText: edge });
  assert.equal((await probeRun(ok.deps)).outcome, "recorded");
});

test("refuses while the legacy lock exists, and while another run holds the project lock", async () => {
  const legacy = setup();
  writeFileSync(legacy.legacy, "held");
  await assert.rejects(probeRun(legacy.deps), /legacy shared lock/);
  assert.equal(legacy.ledgerRows.length, 0);
  const holder = setup();
  await mkdir(holder.lockDir, { recursive: true, mode: 0o700 });
  await writeFile(join(holder.lockDir, `${RECORD_PROJECT}.lock`), "held", { mode: 0o600 });
  await assert.rejects(probeRun(holder.deps), /project lock exists/);
  assert.equal(holder.ledgerRows.length, 0);
  assert.equal(holder.fetchCalls.length, 0);
});

test("the ledger is judged again once the lock is held", async () => {
  let reads = 0;
  const s = setup();
  const original = s.deps.ledger.read;
  s.deps.ledger.read = async () => {
    reads++;
    // A line arrives between the early check and the lock.
    return reads === 1
      ? original()
      : `${JSON.stringify({ ts: "2026-10-02T08:59:00Z", event: "started", taskId: "FS-RULES-SANDBOX", project: RECORD_PROJECT, estimatedUsd: 1 })}\n`;
  };
  await assert.rejects(probeRun(s.deps), /admission/);
  assert.equal(s.fetchCalls.length, 0);
  assert.equal(s.ledgerRows.length, 0);
});

test("a probe packet runs once: any closing row of it, a recovery row included, refuses a second run", async () => {
  const ids = {
    runId: "aaaaaaaaaaaaaaaaaaaa",
    packetId: "probe-v2",
    packetSha256: packet.packetSha256,
    gitSha: COMMIT,
    corpusDigest: "c".repeat(64),
  };
  const closed = encodeRow(
    finishedRow({
      ...ids,
      ts: "2026-09-30T09:00:00Z",
      outcome: "recorded",
      requests: 11,
      estimatedUsd: 0.01,
    }),
  );
  await refused(setup({ ledgerText: closed }), /already run/);
  const stopped = encodeRow(
    finishedRow({
      ...ids,
      ts: "2026-09-30T09:00:00Z",
      outcome: "stopped-clean",
      requests: 1,
      estimatedUsd: 0,
    }),
  );
  await refused(setup({ ledgerText: stopped }), /already run/);
  // Another packet's closing row does not count against this one.
  const other = encodeRow(
    finishedRow({
      ...ids,
      packetSha256: "9".repeat(64),
      ts: "2026-09-30T09:00:00Z",
      outcome: "recorded",
      requests: 11,
      estimatedUsd: 0.01,
    }),
  );
  assert.equal((await probeRun(setup({ ledgerText: other }).deps)).outcome, "recorded");
});

test("this task's own open or recovering run refuses the probe", async () => {
  const ids = {
    runId: "aaaaaaaaaaaaaaaaaaaa",
    packetId: "lean-v2",
    packetSha256: "8".repeat(64),
    gitSha: COMMIT,
    corpusDigest: "c".repeat(64),
  };
  const open = encodeRow(
    startedRow({ ...ids, ts: "2026-09-30T09:00:00Z", maxRequests: 3002, estimatedUsd: 0.5 }),
  );
  await refused(setup({ ledgerText: open }), /admission/);
  const recovering =
    open +
    encodeRow(
      needsRecoveryRow({ ...ids, ts: "2026-09-30T10:00:00Z", requests: 10, estimatedUsd: 0.1 }),
    );
  await refused(setup({ ledgerText: recovering }), /admission/);
});

test("no file of the private run holds the owner token", async () => {
  const s = setup({
    fetch: async (url, init) => {
      const body = String(url).includes("accounts:lookup")
        ? JSON.stringify({ echoed: init.headers.get("authorization") })
        : "{}";
      return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  await probeRun(s.deps);
  const text = JSON.stringify([s.privateFiles, s.ledgerRows]);
  assert.ok(!text.includes(TOKEN), "the token reached a record");
});

test("the probe holds no Web API key and reads no Rules", async () => {
  const s = setup();
  await probeRun(s.deps);
  for (const call of s.fetchCalls) {
    assert.ok(!call.url.includes("key="), call.url);
    assert.ok(!call.url.includes("firebaserules"), call.url);
  }
});

test("another lane's row that names this project among several starts the quiet interval and an open run refuses", async () => {
  const row = (overrides) =>
    `${JSON.stringify({
      taskId: "STORAGE-RULES-SANDBOX",
      project: `${RECORD_PROJECT},fireemu-oracle-idp`,
      estimatedUsd: 0,
      ...overrides,
    })}\n`;
  await refused(
    setup({
      ledgerText: row({
        ts: "2026-10-02T08:54:00.000Z",
        event: "finished",
        outcome: "stopped-clean",
        requests: 17,
        sandboxAtBaseline: true,
      }),
    }),
    /admission/,
  );
  await refused(
    setup({ ledgerText: row({ ts: "2026-09-28T04:00:00.000Z", event: "started" }) }),
    /admission/,
  );
});

// ---- the two sessions, end to end -----------------------------------------------------------------------

const REAL_GCS_UPLOAD = "https://storage.googleapis.com/upload/storage/v1/b";
const REAL_FIREBASE = "https://firebasestorage.googleapis.com/v0/b";

/** A production that starts both sessions with a real-host session URL, and answers the rest 404. */
function sessionFetch(events, { failAt } = {}) {
  let count = 0;
  return async (url, init) => {
    const href = String(url);
    count++;
    events.push({ url: href, method: init.method });
    if (failAt === count) throw new TypeError("fetch failed");
    if (
      init.method === "POST" &&
      href.startsWith(`${REAL_GCS_UPLOAD}/`) &&
      !href.includes("upload_id")
    )
      return new Response("", {
        status: 200,
        headers: {
          location: `${REAL_GCS_UPLOAD}/${new URL(href).pathname.split("/")[5]}/o?uploadType=resumable&name=${new URL(href).searchParams.get("name") && encodeURIComponent(new URL(href).searchParams.get("name"))}&upload_id=AbC-1_x`,
        },
      });
    if (
      init.method === "POST" &&
      href.startsWith(`${REAL_FIREBASE}/`) &&
      href.includes("?name=") &&
      !href.includes("upload_id")
    )
      return new Response("", {
        status: 200,
        headers: {
          "x-goog-upload-status": "active",
          "x-goog-upload-url": `${href}&upload_id=Qz-9_y&upload_protocol=resumable`,
        },
      });
    if (isGcsList(href)) return emptyList();
    return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
  };
}

test("with both sessions started, seventeen requests go out and the run is recorded with that count", async () => {
  const events = [];
  const s = setup({ fetch: sessionFetch(events) });
  const result = await probeRun(s.deps);
  assert.equal(result.outcome, "recorded");
  assert.equal(result.requests, 17);
  assert.equal(events.length, 17);
  assert.equal(s.ledgerRows.at(-1).requests, 17);
  assert.equal(s.ledgerRows[0].maxRequests, 17);
  assert.deepEqual(
    events.slice(7, 15).map((e) => e.method),
    ["POST", "PUT", "DELETE", "PUT", "POST", "POST", "POST", "POST"],
  );
  assert.deepEqual(lockFiles(s), []);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.answers.length, 17);
  assert.equal(meta.answers.filter((row) => row.skipped).length, 0);
});

test("a lost connection on a session's cancel stops the run there, keeps the lock and says where", async () => {
  const events = [];
  const s = setup({ fetch: sessionFetch(events, { failAt: 10 }) });
  await assert.rejects(probeRun(s.deps), (error) => error.afterStart === true);
  assert.equal(events.length, 10, "nothing was sent after the failure");
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.stoppedAt, "gcs-session-cancel");
  assert.equal(meta.requests, 10);
  assert.equal(s.ledgerRows.at(-1).event, "needs-recovery");
  assert.equal(lockFiles(s).length, 1);
});

test("no request of the probe carries object bytes: every body is a JSON description or absent", async () => {
  const bodies = [];
  const s = setup({
    fetch: async (url, init) => {
      bodies.push({
        method: init.method,
        body: init.body ? Buffer.from(init.body).toString() : null,
      });
      return isGcsList(url)
        ? emptyList()
        : new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    },
  });
  await probeRun(s.deps);
  for (const row of bodies) {
    if (row.body === null) continue;
    assert.equal(row.method, "POST");
    assert.doesNotThrow(() => JSON.parse(row.body));
  }
});

// ---- exactness of the checks -----------------------------------------------------------------------------

test("run IDs are checked one by one, and the refusal says nothing else", async () => {
  for (const ids of [
    { runId: "nothex", otherRunId: OTHER },
    { runId: RUN, otherRunId: "nothex" },
    { runId: RUN, otherRunId: RUN },
    { runId: "0123456789ABCDEF0123", otherRunId: OTHER },
    { runId: `${RUN}0`, otherRunId: OTHER },
    { runId: RUN.slice(0, 19), otherRunId: OTHER },
    { runId: RUN, otherRunId: OTHER.slice(1) },
  ]) {
    const s = setup();
    s.deps.ids = ids;
    await assert.rejects(probeRun(s.deps), (error) =>
      /^Error: invalid run ID$/.test(String(error)),
    );
    assert.equal(s.ledgerRows.length, 0);
  }
});

test("another task's line on the project inside the quiet interval refuses the probe, AUTH-FS-CROSS's included", async () => {
  const row = (taskId, ts, project = RECORD_PROJECT) =>
    `${JSON.stringify({ ts, event: "finished", outcome: "recorded", taskId, project, requests: 1, estimatedUsd: 0 })}\n`;
  for (const taskId of [
    "AUTH-FS-CROSS-SANDBOX",
    "STORAGE-RULES-SANDBOX",
    "FUNCTIONS-HTTP-SANDBOX",
  ]) {
    await refused(setup({ ledgerText: row(taskId, "2026-10-02T08:55:00Z") }), /ledger admission/);
    const ok = setup({ ledgerText: row(taskId, "2026-10-02T08:29:00Z") });
    assert.equal((await probeRun(ok.deps)).outcome, "recorded", taskId);
  }
  const otherProject = setup({
    ledgerText: row("AUTH-FS-CROSS-SANDBOX", "2026-10-02T08:55:00Z", "fireemu-oracle-idp"),
  });
  assert.equal((await probeRun(otherProject.deps)).outcome, "recorded");
});

test("only closing rows of this packet, this task and this project make a packet 'already run'", async () => {
  const closed = (overrides) =>
    `${JSON.stringify({
      ts: "2026-09-30T09:00:00Z",
      event: "finished",
      outcome: "recorded",
      taskId: "STORAGE-OBJECT-SANDBOX",
      project: RECORD_PROJECT,
      packetSha256: packet.packetSha256,
      requests: 9,
      estimatedUsd: 0.01,
      ...overrides,
    })}\n`;
  const other = [
    closed({ packetSha256: "0".repeat(64) }),
    closed({ taskId: "OTHER-SANDBOX" }),
    closed({ project: "fireemu-oracle-idp" }),
    closed({ event: "started" }),
    closed({ taskId: undefined }),
  ].join("");
  // A started row of this packet is an open run, judged by the admission and not by this check;
  // the others simply do not count.
  const withoutStarted = other
    .split("\n")
    .filter((line) => !line.includes('"started"'))
    .join("\n");
  assert.equal((await probeRun(setup({ ledgerText: withoutStarted }).deps)).outcome, "recorded");
  await refused(setup({ ledgerText: closed({}) }), /already run/);
});

test("a token that appears in an error is scrubbed from the private summary and cut to a short line", async () => {
  const long = "y".repeat(400);
  const s = setup({
    fetch: async (url, init) => {
      throw new TypeError(`fetch failed for ${init.headers.get("authorization")}\n${long}`);
    },
  });
  await assert.rejects(probeRun(s.deps), /fetch failed/);
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.status, "THROWN");
  assert.equal(JSON.stringify(s.privateFiles).includes(TOKEN), false);
  assert.ok(meta.reason.length <= 200);
  assert.ok(!meta.reason.includes("\n"));
  assert.match(meta.reason, /^fetch failed for /);
  assert.equal(meta.reason.includes(long.slice(0, 50)), false, "only the first line");
});

test("the result of a recorded run carries the answers, and the private summary says PROBE_COMPLETE", async () => {
  const s = setup();
  const result = await probeRun(s.deps);
  assert.equal(result.answers.length, 17, "eleven answered, six skipped");
  assert.equal(result.answers[0].id, "identity-owner-lookup");
  assert.equal(s.privateFiles.meta.at(-1).status, "PROBE_COMPLETE");
  assert.equal(s.privateFiles.meta.at(-1).outcome, "recorded");
});

test("a started row of this packet that another packet's closing row ended is not a closing row of it", async () => {
  const base = {
    taskId: "STORAGE-OBJECT-SANDBOX",
    project: RECORD_PROJECT,
    estimatedUsd: 0.01,
    packetId: "x",
    gitSha: COMMIT,
    corpusDigest: "c".repeat(64),
  };
  const ledgerText = [
    {
      ...base,
      ts: "2026-09-30T06:00:00Z",
      event: "started",
      runId: "aaaaaaaaaaaaaaaaaaaa",
      packetSha256: packet.packetSha256,
      maxRequests: 9,
    },
    {
      ...base,
      ts: "2026-09-30T06:05:00Z",
      event: "finished",
      outcome: "recorded",
      runId: "bbbbbbbbbbbbbbbbbbbb",
      packetSha256: "7".repeat(64),
      requests: 9,
      sandboxAtBaseline: true,
    },
  ]
    .map((row) => `${JSON.stringify(row)}\n`)
    .join("");
  assert.equal((await probeRun(setup({ ledgerText }).deps)).outcome, "recorded");
});

test("the rows of a run carry the probe's estimate, whether it ended or stopped", async () => {
  const done = setup();
  await probeRun(done.deps);
  assert.equal(done.ledgerRows.at(-1).estimatedUsd, 0.01);
  const lost = setup({
    fetch: async () => {
      throw new TypeError("fetch failed");
    },
  });
  await assert.rejects(probeRun(lost.deps));
  assert.equal(lost.ledgerRows.at(-1).estimatedUsd, 0.01);
});

test("a first line of an error that is itself long is cut to 200 characters", async () => {
  const s = setup({
    fetch: async () => {
      throw new TypeError(`z${"y".repeat(400)}`);
    },
  });
  await assert.rejects(probeRun(s.deps));
  assert.equal(s.privateFiles.meta.at(-1).reason.length, 200);
});

// ---- the readback before the baseline is claimed -------------------------------------------------------

test("a prefix that reads back with an item closes as needs-recovery, not as recorded, and keeps the lock", async () => {
  const s = setup({
    fetch: async (url) =>
      isGcsList(url)
        ? new Response('{"items":[{"name":"storage-object/x/probe/session-firebase.bin"}]}', {
            status: 200,
            headers: { "content-type": "application/json" },
          })
        : new Response("{}", { status: 404, headers: { "content-type": "application/json" } }),
  });
  await assert.rejects(probeRun(s.deps), (error) => {
    assert.equal(error.afterStart, true);
    assert.match(error.message, /not read back as empty/);
    return true;
  });
  const closing = s.ledgerRows.at(-1);
  assert.equal(closing.event, "needs-recovery");
  assert.equal(closing.outcome, "needs-recovery");
  assert.equal(closing.sandboxAtBaseline, false);
  assert.equal(closing.requests, 11, "everything was sent, and it is all counted");
  assert.equal(lockFiles(s).length, 1);
  assert.equal(
    s.ledgerRows.some((row) => row.event === "finished"),
    false,
  );
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.outcome, "needs-recovery");
  assert.equal(meta.stoppedAt, "gcs-list-owner");
  assert.equal(meta.answered.length, 17);
});

test("a GCS list that is not a 200, or that has a next page, is not an empty prefix either", async () => {
  for (const [status, body] of [
    [404, "{}"],
    [403, "{}"],
    [500, "{}"],
    [200, '{"nextPageToken":"t"}'],
    [200, "not json"],
  ]) {
    const s = setup({
      fetch: async (url) =>
        isGcsList(url)
          ? new Response(body, { status, headers: { "content-type": "application/json" } })
          : new Response("{}", { status: 404, headers: { "content-type": "application/json" } }),
    });
    await assert.rejects(probeRun(s.deps), /not read back as empty/, `${status} ${body}`);
    assert.equal(lockFiles(s).length, 1);
  }
});

test("only the GCS list closes the run: the Firebase list may answer anything", async () => {
  const s = setup({
    fetch: async (url) =>
      isGcsList(url)
        ? emptyList()
        : String(url).startsWith("https://firebasestorage.googleapis.com/v0/b/") &&
            String(url).includes("?prefix=")
          ? new Response("boom", { status: 500 })
          : new Response("{}", { status: 404, headers: { "content-type": "application/json" } }),
  });
  assert.equal((await probeRun(s.deps)).outcome, "recorded");
});

test("the token failing during a session stops the run as needs-recovery, and the reason names no secret", async () => {
  let tokens = 0;
  const events = [];
  const s = setup({
    fetch: sessionFetch(events),
    deps: {
      getToken: async () => {
        if (++tokens > 6) throw new Error("gcloud printed ya29.secret-value-that-must-not-be-kept");
        return TOKEN;
      },
    },
  });
  await assert.rejects(probeRun(s.deps), (error) => error.afterStart === true);
  assert.equal(events.length, 8, "nothing was sent after the token failed");
  const meta = s.privateFiles.meta.at(-1);
  assert.equal(meta.stoppedAt, "gcs-session-status");
  assert.equal(JSON.stringify(s.privateFiles).includes("secret-value"), false);
  assert.equal(s.ledgerRows.at(-1).event, "needs-recovery");
  assert.equal(lockFiles(s).length, 1);
});
