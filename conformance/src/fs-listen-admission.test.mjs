import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MIN_SPACING_MS,
  TASK_ID,
  checkAdmission,
  lockPathOf,
  namesProject,
  projectRows,
} from "./fs-listen/admission.mjs";

const LEDGER = "/runs/sandbox-ledger.jsonl";
const NOW = Date.parse("2026-10-05T12:00:00.000Z");
const ENVELOPE = "LISTEN-L1-SDK-001";
const minutesAgo = (m) => new Date(NOW - m * 60_000).toISOString();
const row = (project, event, minutes, extra = {}) =>
  JSON.stringify({ ts: minutesAgo(minutes), event, project, taskId: "OTHER-TASK", ...extra });
const HOLDER = JSON.stringify({
  taskId: TASK_ID,
  envelopeId: ENVELOPE,
  pid: 1,
  acquiredAt: minutesAgo(1),
});
// The coordinator's own start row for this envelope, written before the launch.
const ownStart = (project, minutes = 0) =>
  row(project, "started", minutes, { taskId: TASK_ID, envelopeId: ENVELOPE });

// Literal row shapes of the live ledger (ids and hashes shortened).
const STORAGE_RESERVED = (minutes) =>
  JSON.stringify({
    ts: minutesAgo(minutes),
    event: "reserved",
    taskId: "STORAGE-RULES-SANDBOX",
    project: "fireemu-oracle-query",
    packetId: "stage2b-v1",
    envelopeId: "STORAGE-RULES-stage2b-v1-001",
    runId: "stage2b-20260929a",
    maxRequests: 8,
    estimatedUsd: 1,
  });
const STORAGE_FINISHED = (minutes) =>
  JSON.stringify({
    ts: minutesAgo(minutes),
    event: "finished",
    taskId: "STORAGE-RULES-SANDBOX",
    project: "fireemu-oracle-query",
    envelopeId: "STORAGE-RULES-stage2b-v1-001",
    outcome: "preflight-failed",
    requests: 2,
  });
const TXN = (outcome, minutes, attempt) =>
  JSON.stringify({
    attemptId: attempt,
    database: "(default)",
    envelopeId: "FS-TRANSACTION-p14-stage2-001",
    estimatedUsd: 0.0,
    outcome,
    packetId: "fs-transaction-p14-stage2-a003",
    project: "fireemu-oracle-txn",
    requests: outcome === "reserved" ? null : 45,
    taskId: "FS-TRANSACTION-SANDBOX",
    ts: minutesAgo(minutes),
  });
const COMMA = (event, minutes) =>
  row("fireemu-oracle-query,fireemu-oracle-idp", event, minutes, {
    taskId: "STORAGE-RULES-SANDBOX",
  });

/** Files by path; a missing path is ENOENT. */
function files(map) {
  return {
    readFile: async (path) => {
      if (!Object.hasOwn(map, path)) throw Object.assign(new Error("no file"), { code: "ENOENT" });
      return map[path];
    },
  };
}
const LOCK = lockPathOf(LEDGER, "fireemu-oracle-query");
const admit = (map, project = "fireemu-oracle-query", envelope = ENVELOPE) =>
  checkAdmission({ ledger: LEDGER, project, envelope, now: () => NOW, ...files(map) });

test("the lock of a project is a file beside the ledger, named for the project", () => {
  assert.equal(LOCK, "/runs/sandbox-locks/fireemu-oracle-query.lock");
  assert.equal(
    lockPathOf(LEDGER, "fireemu-oracle-txn"),
    "/runs/sandbox-locks/fireemu-oracle-txn.lock",
  );
  assert.throws(() => lockPathOf(LEDGER, "../x"), /is not a project ID/);
  assert.throws(() => lockPathOf(LEDGER, ""), /is not a project ID/);
});

test("a run is admitted when the coordinator holds the lock of this envelope and the latest row is old enough", async () => {
  const ledger = [row("fireemu-oracle-query", "finished", 45, { outcome: "recorded" })].join("\n");
  const out = await admit({ [LOCK]: `${HOLDER}\n`, [LEDGER]: `${ledger}\n` });
  assert.equal(out.holder.taskId, TASK_ID);
  assert.equal(out.latestRowAt, minutesAgo(45));
});

test("no lock, an unreadable lock, or an empty one refuses", async () => {
  await assert.rejects(admit({ [LEDGER]: "" }), /is not held/);
  await assert.rejects(admit({ [LOCK]: "not json", [LEDGER]: "" }), /does not name a holder/);
  await assert.rejects(admit({ [LOCK]: "{}", [LEDGER]: "" }), /does not name a holder/);
  await assert.rejects(admit({ [LOCK]: "[]", [LEDGER]: "" }), /does not name a holder/);
  await assert.rejects(
    admit({ [LOCK]: JSON.stringify({ taskId: "" }), [LEDGER]: "" }),
    /does not name a holder/,
  );
});

test("another runner's own lock does not admit (a foreign holder, or another envelope)", async () => {
  // The FS-TRANSACTION runner takes sandbox-locks/<project>.lock itself, with its own task id.
  const foreign = JSON.stringify({
    acquiredAt: minutesAgo(1),
    packetId: "fs-transaction-p14-stage2-a003",
    pid: 99617,
    taskId: "FS-TRANSACTION-SANDBOX",
  });
  await assert.rejects(admit({ [LOCK]: foreign, [LEDGER]: "" }), /held by FS-TRANSACTION-SANDBOX/);
  const other = JSON.stringify({ taskId: TASK_ID, envelopeId: "LISTEN-L1-NATIVE-001" });
  await assert.rejects(admit({ [LOCK]: other, [LEDGER]: "" }), /not held for envelope/);
  const none = JSON.stringify({ taskId: TASK_ID });
  await assert.rejects(admit({ [LOCK]: none, [LEDGER]: "" }), /not held for envelope/);
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: "" }, "fireemu-oracle-query", "LISTEN-L1-NATIVE-001"),
    /not held for envelope/,
  );
});

test("an envelope id is required, and it must not be empty", async () => {
  for (const envelope of [undefined, ""])
    await assert.rejects(
      checkAdmission({
        ledger: LEDGER,
        project: "fireemu-oracle-query",
        envelope,
        now: () => NOW,
        ...files({ [LOCK]: HOLDER, [LEDGER]: "" }),
      }),
      /--envelope/,
    );
});

test("the legacy shared lock refuses too, whoever holds the project lock", async () => {
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [`${LEDGER}.lock`]: "x", [LEDGER]: "" }),
    /legacy shared lock/,
  );
});

test("the latest row must be at least 30 minutes old", async () => {
  assert.equal(MIN_SPACING_MS, 30 * 60_000);
  for (const [minutes, ok] of [
    [0, false],
    [29, false],
    [29.99, false],
    [30, true],
    [31, true],
  ]) {
    const ledger = row("fireemu-oracle-query", "finished", minutes, { outcome: "recorded" });
    const promise = admit({ [LOCK]: HOLDER, [LEDGER]: ledger });
    if (ok) await promise;
    else await assert.rejects(promise, /only .* minutes old/, `${minutes}`);
  }
});

test("cleanup-verified and finished rows end a run; another project's rows do not count", async () => {
  for (const event of ["cleanup-verified", "finished"])
    await assert.rejects(
      admit({ [LOCK]: HOLDER, [LEDGER]: row("fireemu-oracle-query", event, 5) }),
      /only 5 minutes old/,
    );
  const others = [
    row("fireemu-oracle-txn", "finished", 1),
    row("fireemu-oracle-events", "needs-recovery", 2),
  ].join("\n");
  await admit({ [LOCK]: HOLDER, [LEDGER]: others });
  // The latest row decides, whatever the order of the lines.
  const mixed = [
    row("fireemu-oracle-query", "finished", 5),
    row("fireemu-oracle-query", "finished", 90),
  ].join("\n");
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: mixed }), /only 5 minutes old/);
});

test("a needs-recovery row opens a run until a later end of the same task", async () => {
  const recovery = row("fireemu-oracle-query", "needs-recovery", 120, { taskId: "T" });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: recovery }), /has no end/);
  const recovered = [
    recovery,
    row("fireemu-oracle-query", "cleanup-verified", 100, { taskId: "T" }),
  ].join("\n");
  await admit({ [LOCK]: HOLDER, [LEDGER]: recovered });
  // An end of another task does not close it.
  const foreignEnd = [recovery, row("fireemu-oracle-query", "finished", 100, { taskId: "U" })];
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: foreignEnd.join("\n") }), /has no end/);
});

test("a run that started and never ended refuses: another run may be live or need recovery", async () => {
  const started = row("fireemu-oracle-query", "started", 120);
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: started }), /OTHER-TASK, started/);
  const ended = [started, row("fireemu-oracle-query", "finished", 100)].join("\n");
  await admit({ [LOCK]: HOLDER, [LEDGER]: ended });
});

test("the coordinator's own started row of this envelope is the one open row allowed, and it is not a recent row", async () => {
  const project = "fireemu-oracle-query";
  const old = row(project, "finished", 90, { taskId: "STORAGE-RULES-SANDBOX" });
  const out = await admit({ [LOCK]: HOLDER, [LEDGER]: [old, ownStart(project, 0)].join("\n") });
  assert.equal(out.latestRowAt, minutesAgo(90));
  // A started row of another envelope, or of another task, is a foreign open run.
  for (const extra of [
    { envelopeId: "LISTEN-L1-NATIVE-001" },
    { taskId: "STORAGE-RULES-SANDBOX" },
    { event: "reserved" },
  ]) {
    const other = JSON.stringify({ ...JSON.parse(ownStart(project, 0)), ...extra });
    await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: other }), /has no end/, `${extra}`);
  }
  // A second open row, even of this envelope, refuses: only one start may be open.
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: [ownStart(project, 90), ownStart(project, 0)].join("\n") }),
    /has no end/,
  );
  // A foreign open row refuses even beside the own start.
  await assert.rejects(
    admit({
      [LOCK]: HOLDER,
      [LEDGER]: [row(project, "started", 90), ownStart(project, 0)].join("\n"),
    }),
    /OTHER-TASK, started/,
  );
});

test("the FS-TRANSACTION rows without an event: reserved opens a run, any other outcome ends it", async () => {
  const project = "fireemu-oracle-txn";
  const lock = lockPathOf(LEDGER, project);
  const at = (rows) => admit({ [lock]: HOLDER, [LEDGER]: rows.join("\n") }, project);
  // P14 shape: a reservation one minute old.
  await assert.rejects(
    at([TXN("reserved", 1, "a1")]),
    /FS-TRANSACTION-SANDBOX, undefined|has no end/,
  );
  await assert.rejects(at([TXN("reserved", 120, "a1")]), /has no end/);
  // Recorded 0 minutes ago: ended, but the spacing is not over.
  await assert.rejects(
    at([TXN("reserved", 10, "a1"), TXN("recorded", 0, "a1")]),
    /only 0 minutes old/,
  );
  await at([TXN("reserved", 100, "a1"), TXN("recorded", 90, "a1")]);
  // Two attempts of one task: the second reservation is open until its own end.
  await assert.rejects(
    at([TXN("reserved", 100, "a1"), TXN("recorded", 90, "a1"), TXN("reserved", 80, "a2")]),
    /has no end/,
  );
});

test("STORAGE-RULES rows with event reserved, and rows whose project is a comma-joined list", async () => {
  const q = "fireemu-oracle-query";
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: STORAGE_RESERVED(1) }), /has no end/);
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: STORAGE_RESERVED(120) }), /has no end/);
  await admit({
    [LOCK]: HOLDER,
    [LEDGER]: [STORAGE_RESERVED(120), STORAGE_FINISHED(100)].join("\n"),
  });
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: [STORAGE_RESERVED(120), STORAGE_FINISHED(2)].join("\n") }),
    /only 2 minutes old/,
  );
  // The comma-joined project names query and idp alike.
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: COMMA("started", 120) }), /has no end/);
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: COMMA("finished", 3) }),
    /only 3 minutes old/,
  );
  const idp = lockPathOf(LEDGER, "fireemu-oracle-idp");
  await assert.rejects(
    admit({ [idp]: HOLDER, [LEDGER]: COMMA("finished", 3) }, "fireemu-oracle-idp"),
    /only 3 minutes old/,
  );
  // A substring of a project id is not the project.
  await admit({ [LOCK]: HOLDER, [LEDGER]: row("fireemu-oracle-query-two", "started", 1) });
  assert.equal(namesProject({ project: ["a", q] }, q), true);
  assert.equal(namesProject({ project: `a, ${q}` }, q), true);
  assert.equal(namesProject({ project: `x${q}` }, q), false);
  assert.equal(namesProject({ project: 7 }, q), false);
  assert.equal(namesProject({}, q), false);
});

test("GO rows (a launch authorisation) open a run, and rows without ts use issuedAt", async () => {
  const go = JSON.stringify({
    event: "GO",
    project: "fireemu-oracle-query",
    task: "PUBSUB-EVENTARC",
    issuedAt: NOW - 120 * 60_000,
  });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: go }), /PUBSUB-EVENTARC, GO/);
  const finished = row("fireemu-oracle-query", "finished", 100, {
    taskId: undefined,
    task: "PUBSUB-EVENTARC",
  });
  await admit({ [LOCK]: HOLDER, [LEDGER]: [go, finished].join("\n") });
});

test("the spacing is measured from the latest row of any kind, notes and changes included", async () => {
  for (const event of ["note", "change", "config-change", "progress"]) {
    const ledger = [
      row("fireemu-oracle-query", "finished", 90),
      row("fireemu-oracle-query", event, 1),
    ].join("\n");
    await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: ledger }), /only 1 minutes old/, event);
    // Such a row opens no run: once it is old enough the project is admitted.
    await admit({
      [LOCK]: HOLDER,
      [LEDGER]: row("fireemu-oracle-query", event, 40),
    });
  }
});

test("a read-only stop is exempt from the spacing only when its row says so (ledger 821)", async () => {
  const project = "fireemu-oracle-query";
  const start = row(project, "started", 3, { taskId: "T" });
  const stop = (extra) =>
    row(project, "finished", 2, { taskId: "T", outcome: "stopped-clean", ...extra });
  const old = row(project, "finished", 90, { taskId: "U" });
  // The stop and the start it closed do not count: the old row decides.
  const out = await admit({
    [LOCK]: HOLDER,
    [LEDGER]: [old, start, stop({ readOnlyStop: true })].join("\n"),
  });
  assert.equal(out.latestRowAt, minutesAgo(90));
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: [old, start, stop({})].join("\n") }),
    /only 2 minutes old/,
  );
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: [old, start, stop({ readOnlyStop: "yes" })].join("\n") }),
    /only 2 minutes old/,
  );
  await assert.rejects(
    admit({
      [LOCK]: HOLDER,
      [LEDGER]: [old, start, stop({ outcome: "recorded", readOnlyStop: true })].join("\n"),
    }),
    /only 2 minutes old/,
    "only a stopped-clean run can be a read-only stop",
  );
  await assert.rejects(
    admit({
      [LOCK]: HOLDER,
      [LEDGER]: [old, row(project, "needs-recovery", 2, { readOnlyStop: true })].join("\n"),
    }),
    /has no end/,
  );
  // A later row of another kind removes the exemption.
  await assert.rejects(
    admit({
      [LOCK]: HOLDER,
      [LEDGER]: [old, start, stop({ readOnlyStop: true }), row(project, "note", 1)].join("\n"),
    }),
    /only 1 minutes old/,
  );
});

test("a ledger line that cannot be read but names the project refuses; one that does not is skipped", async () => {
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: '{"project":"fireemu-oracle-query", broken' }),
    /cannot be read/,
  );
  await admit({ [LOCK]: HOLDER, [LEDGER]: '{"project":"fireemu-oracle-txn", broken\n\n   \n' });
  await assert.rejects(admit({ [LOCK]: HOLDER }), /ledger .* cannot be read/);
});

test("a row without a readable time refuses", async () => {
  for (const bad of [
    { event: "finished", project: "fireemu-oracle-query", ts: "yesterday" },
    { event: "note", project: "fireemu-oracle-query" },
  ])
    await assert.rejects(
      admit({ [LOCK]: HOLDER, [LEDGER]: JSON.stringify(bad) }),
      /no readable time/,
    );
});

test("projectRows returns the rows of one project and the runs still open", () => {
  const lines = [
    row("p", "started", 100),
    row("p", "finished", 90),
    row("p", "started", 60),
    row("q", "finished", 1),
  ];
  const { entries, open } = projectRows(lines.join("\n"), "p");
  assert.equal(entries.length, 3);
  assert.deepEqual(
    open.map((entry) => entry.row.ts),
    [minutesAgo(60)],
  );
  assert.deepEqual(projectRows("", "p"), { entries: [], open: [] });
});

test("a file that cannot be read for another reason than being absent is an error, not an absence", async () => {
  const failing = (path, code) => ({
    readFile: async (p) => {
      if (p === path) throw Object.assign(new Error("denied"), { code });
      if (p === LOCK) return HOLDER;
      if (p === LEDGER) return "";
      throw Object.assign(new Error("no file"), { code: "ENOENT" });
    },
  });
  for (const path of [LOCK, LEDGER, `${LEDGER}.lock`])
    await assert.rejects(
      checkAdmission({
        ledger: LEDGER,
        project: "fireemu-oracle-query",
        envelope: ENVELOPE,
        now: () => NOW,
        ...failing(path, "EACCES"),
      }),
      /denied/,
      path,
    );
});

test("files are read as text", async () => {
  const seen = [];
  await checkAdmission({
    ledger: LEDGER,
    project: "fireemu-oracle-query",
    envelope: ENVELOPE,
    now: () => NOW,
    readFile: async (path, encoding) => {
      seen.push(encoding);
      if (path === LOCK) return HOLDER;
      if (path === LEDGER) return "";
      throw Object.assign(new Error("no file"), { code: "ENOENT" });
    },
  });
  assert.deepEqual(seen, ["utf8", "utf8", "utf8"]);
});

test("a note, change or progress row of the same task does not end an open run", async () => {
  for (const event of ["note", "change", "progress", "config-change", "GO-no", "project-deleted"]) {
    const ledger = [
      row("fireemu-oracle-query", "started", 120, { taskId: "T" }),
      row("fireemu-oracle-query", event, 100, { taskId: "T" }),
    ].join("\n");
    await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: ledger }), /has no end/, event);
  }
});

test("a row with neither an event nor an outcome is a plain row: it opens nothing, ends nothing, and counts for the spacing", async () => {
  const bare = JSON.stringify({
    ts: minutesAgo(100),
    project: "fireemu-oracle-query",
    taskId: "T",
  });
  await admit({ [LOCK]: HOLDER, [LEDGER]: bare });
  const open = row("fireemu-oracle-query", "started", 120, { taskId: "T" });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: [open, bare].join("\n") }), /has no end/);
  const recent = JSON.stringify({ ts: minutesAgo(1), project: "fireemu-oracle-query" });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: recent }), /only 1 minutes old/);
});

test("the refusal for an open run names its task, its event or outcome and its time", async () => {
  const project = "fireemu-oracle-query";
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: row(project, "started", 120, { taskId: "T-1" }) }),
    (error) => error.message.includes("T-1, started") && error.message.includes(minutesAgo(120)),
  );
  const noTask = JSON.stringify({ ts: minutesAgo(120), project, event: "started" });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: noTask }), (error) =>
    /\(no task, started\)/.test(error.message),
  );
  const outcomeOnly = JSON.stringify({
    ts: minutesAgo(120),
    project,
    outcome: "reserved",
    task: "X",
  });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: outcomeOnly }), (error) =>
    /\(X, reserved\)/.test(error.message),
  );
});

test("two starts of this very envelope are two open runs: neither is the allowed one", async () => {
  const project = "fireemu-oracle-query";
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: [ownStart(project, 50), ownStart(project, 40)].join("\n") }),
    /has no end/,
  );
  // One own start alone is fine, and the earlier row decides the spacing.
  const out = await admit({
    [LOCK]: HOLDER,
    [LEDGER]: [row(project, "finished", 45), ownStart(project, 0)].join("\n"),
  });
  assert.equal(out.latestRowAt, minutesAgo(45));
});

test("when nothing else counts, the latest row is reported as undefined and the run is admitted", async () => {
  const out = await admit({ [LOCK]: HOLDER, [LEDGER]: ownStart("fireemu-oracle-query", 0) });
  assert.equal(out.latestRowAt, undefined);
});
