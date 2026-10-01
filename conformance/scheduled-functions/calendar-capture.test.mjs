import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, mkdir, readFile, writeFile, lstat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  captureCalendar,
  captureCalendarRecovery,
  calendarCorpusDigest,
  harnessDigest,
} from "./capture.mjs";

import { calendarRequests } from "./calendar.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);
const clock = () => new Date("2026-09-30T09:00:00Z");

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "fireemu-calendar-admission-"));
  t.after(() => rm(root, { recursive: true }));
  const runs = join(root, "docs.local/runs"),
    lane = join(runs, "codex-lane8"),
    locks = join(runs, "sandbox-locks"),
    instructions = join(root, "docs.local/instructions");
  await mkdir(lane, { recursive: true, mode: 0o700 });
  await mkdir(locks, { mode: 0o700 });
  await mkdir(instructions);
  const guard = join(locks, "fireemu-oracle-sbx.recovery-guard"),
    ledger = join(runs, "sandbox-ledger.jsonl"),
    owner = join(instructions, "owner-decisions.md");
  await writeFile(guard, "fake foreign guard", { mode: 0o600 });
  await writeFile(ledger, "", { mode: 0o600 });
  const plan = {
    schemaVersion: 1,
    kind: "calendar-seed",
    project: "fireemu-oracle-sbx",
    projectNumber: "123456789012",
    runId: "b1".repeat(8),
    sourceCommit,
    harnessDigest: await harnessDigest("calendar-seed"),
    corpusDigest: await calendarCorpusDigest(),
    maxRequests: 64,
    reserveUsd: 0.25,
    maxExtraRequests: 3,
  };
  const packetPath = join(lane, "calendar-packet.json");
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
      assert.ok((await readFile(ledger, "utf8")).includes('"event":"started"'));
      await lstat(join(locks, "fireemu-oracle-sbx.lock"));
      return "fake-calendar-token";
    },
    send: async () => {
      sends++;
      return new Response("{}", { status: 403 });
    },
  };
  const reset = async (overrides = {}, subject = "SCHEDULED-FUNCTIONS calendar seed packet") => {
    Object.assign(plan, overrides);
    const bytes = JSON.stringify(plan);
    await writeFile(packetPath, bytes, { mode: 0o600 });
    await writeFile(
      owner,
      `- 2026-09-30 | ${subject} | decision=APPROVE; packetSha256=${sha256(bytes)}; sourceCommit=${plan.sourceCommit}; harnessDigest=${plan.harnessDigest}; corpusDigest=${plan.corpusDigest}; maxRequests=64; reserveUsd=0.25; maxExtraRequests=3; maxDeleteAttemptsPerJob=3; originalRunId=${plan.originalRunId ?? ""}; originalPacketSha256=${plan.originalPacketSha256 ?? ""} | Claude（調整役。委任） | fake fixture\n`,
    );
    return bytes;
  };
  await reset();
  return {
    root,
    runs,
    lane,
    locks,
    guard,
    ledger,
    owner,
    plan,
    options,
    reset,
    counts: () => ({ tokens, sends }),
  };
}

test("calendar capture reserves before one provider call, pins rawpacket and retains lock for review", async (t) => {
  const f = await fixture(t),
    bytes = await readFile(f.options.packetPath);
  let result;
  await assert.doesNotReject(async () => {
    result = await captureCalendar(f.options);
  });
  assert.equal(result.outcome, "calendar-needs-review");
  assert.deepEqual(f.counts(), { tokens: 1, sends: 1 });
  assert.equal(result.cleanupVerified, false);
  assert.equal(await readFile(f.guard, "utf8"), "fake foreign guard");
  await assert.doesNotReject(() => lstat(join(f.locks, "fireemu-oracle-sbx.lock")));
  assert.deepEqual(await readFile(join(result.directory, "raw-packet.json")), bytes);
  const ledger = await readFile(f.ledger, "utf8");
  assert.ok(ledger.includes('"event":"needs-recovery"'));
  assert.ok(!ledger.includes("fake-calendar-token"));
});

test("calendar admission refuses every altered source/corpus/mode/ceiling before credentials", async (t) => {
  for (const overrides of [
    { sourceCommit: "c".repeat(40) },
    { harnessDigest: "d".repeat(64) },
    { corpusDigest: "e".repeat(64) },
    { kind: "shape" },
    { maxRequests: 65 },
    { reserveUsd: 1 },
    { maxExtraRequests: 4 },
  ]) {
    const f = await fixture(t);
    await f.reset(overrides);
    await assert.rejects(captureCalendar(f.options), /binding|source|runner|corpus|packet/);
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
    assert.equal(await readFile(f.ledger, "utf8"), "");
  }
});

test("old shape approval or withdrawal cannot authorize the new calendar mode", async (t) => {
  for (const kind of ["old-subject", "withdrawn"]) {
    const f = await fixture(t);
    if (kind === "old-subject") await f.reset({}, "SCHEDULED-FUNCTIONS stage-2 shape packet");
    else {
      const approval = await readFile(f.owner, "utf8");
      await writeFile(
        f.owner,
        approval + approval.replace("decision=APPROVE", "decision=WITHDRAWN"),
      );
    }
    await assert.rejects(captureCalendar(f.options), /approval/);
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
  }
});

test("held project lock or reused calendar attempt fails before reservation/provider", async (t) => {
  for (const kind of ["lock", "replay"]) {
    const f = await fixture(t);
    if (kind === "lock")
      await writeFile(join(f.locks, "fireemu-oracle-sbx.lock"), "another fake owner");
    else
      await writeFile(
        f.ledger,
        JSON.stringify({
          project: f.plan.project,
          taskId: "SCHEDULED-FUNCTIONS",
          attemptId: f.plan.runId,
          packetSha256: "f".repeat(64),
          event: "finished",
          sandboxAtBaseline: true,
          estimatedUsd: 0.25,
          ts: "2026-09-30T08:00:00Z",
        }) + "\n",
      );
    await assert.rejects(captureCalendar(f.options), /lock|already started/);
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
  }
});

test("calendar seed refuses an open attempt hidden by another attempt's terminal row", async (t) => {
  const f = await fixture(t);
  const rows = [
    {
      project: f.plan.project,
      taskId: "SCHEDULED-FUNCTIONS",
      attemptId: "a1".repeat(8),
      event: "needs-recovery",
      outcome: "calendar-needs-review",
      sandboxAtBaseline: false,
      estimatedUsd: 0.25,
      ts: "2026-09-30T07:00:00Z",
    },
    {
      project: f.plan.project,
      taskId: "SCHEDULED-FUNCTIONS",
      attemptId: "d1".repeat(8),
      event: "finished",
      outcome: "reviewed",
      sandboxAtBaseline: true,
      estimatedUsd: 0.25,
      ts: "2026-09-30T08:00:00Z",
    },
  ];
  const bytes = rows.map(JSON.stringify).join("\n") + "\n";
  await writeFile(f.ledger, bytes);
  await assert.rejects(captureCalendar(f.options), /sandbox admission refused/);
  assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
  assert.equal(await readFile(f.ledger, "utf8"), bytes);
  await assert.rejects(lstat(join(f.locks, "fireemu-oracle-sbx.lock")), { code: "ENOENT" });
});

test("calendar recovery mode cannot consume a calendar-seed approval or packet", async (t) => {
  const f = await fixture(t);
  await assert.rejects(captureCalendarRecovery(f.options), /binding|source|runner|packet/);
  assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
});

async function recoveryFixture(t) {
  const f = await fixture(t),
    originalRunId = "c1".repeat(8),
    originalSourceCommit = "f".repeat(40),
    originalHarnessDigest = "e".repeat(64);
  const originalPacket = {
    schemaVersion: 1,
    kind: "calendar-seed",
    project: f.plan.project,
    projectNumber: f.plan.projectNumber,
    runId: originalRunId,
    sourceCommit: originalSourceCommit,
    harnessDigest: originalHarnessDigest,
    corpusDigest: f.plan.corpusDigest,
    maxRequests: 64,
    reserveUsd: 0.25,
    maxExtraRequests: 3,
  };
  const bytes = JSON.stringify(originalPacket),
    originalPacketSha256 = sha256(bytes),
    folder = join(f.lane, "calendar-" + originalRunId);
  await mkdir(folder, { mode: 0o700 });
  await writeFile(join(folder, "raw-packet.json"), bytes, { mode: 0o600 });
  const journal =
    JSON.stringify({
      id: "identity",
      state: "before-send",
      method: "GET",
      url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-sbx/releases/cloud.firestore",
      dispatchAt: "2026-09-30T08:00:00Z",
    }) + "\n";
  await writeFile(join(folder, "requests.jsonl"), journal, { mode: 0o600 });
  const row = {
    project: f.plan.project,
    taskId: "SCHEDULED-FUNCTIONS",
    attemptId: originalRunId,
    packetSha256: originalPacketSha256,
    gitSha: originalSourceCommit,
    harnessDigest: originalHarnessDigest,
    corpusDigest: f.plan.corpusDigest,
    kind: "calendar-seed",
    event: "needs-recovery",
    outcome: "calendar-needs-review",
    sandboxAtBaseline: false,
    requests: 1,
    estimatedUsd: 0.25,
    ts: "2026-09-30T08:00:00Z",
  };
  const line = JSON.stringify(row);
  await writeFile(f.ledger, line + "\n");
  await f.reset(
    {
      kind: "calendar-recovery",
      harnessDigest: await harnessDigest("calendar-recovery"),
      maxDeleteAttemptsPerJob: 3,
      originalRunId,
      originalPacketSha256,
      originalSourceCommit,
      originalHarnessDigest,
      originalCorpusDigest: f.plan.corpusDigest,
      originalRequests: 1,
      originalJournalSha256: sha256(journal),
      originalLedgerRowSha256: sha256(line),
    },
    "SCHEDULED-FUNCTIONS calendar recovery packet",
  );
  f.options.send = async (request) => {
    f.options.sendCount = (f.options.sendCount ?? 0) + 1;
    if (request.id.endsWith("-before") || request.id.endsWith("-after")) {
      const topic = request.id.startsWith("read-topic");
      return new Response(
        JSON.stringify({
          error: {
            code: 404,
            status: "NOT_FOUND",
            message: topic
              ? "Resource not found (resource=fe-scheduled-calendar-" + originalRunId + ")."
              : "Job not found.",
          },
        }),
        { status: 404 },
      );
    }
    return new Response("{}", { status: 200 });
  };
  return f;
}

test("calendar recovery binds dynamic original count and rawpacket before provider and retains both debts", async (t) => {
  const f = await recoveryFixture(t);
  let result;
  await assert.doesNotReject(async () => {
    result = await captureCalendarRecovery(f.options);
  });
  assert.equal(result.outcome, "calendar-recovery-needs-review");
  assert.equal(result.attempted, 20);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.equal(f.counts().tokens, 1);
  const rows = (await readFile(f.ledger, "utf8")).trim().split("\n").map(JSON.parse);
  assert.equal(rows.length, 3);
  assert.equal(rows.at(-1).requests, 20);
  assert.equal(rows.at(-1).event, "needs-recovery");
  assert.equal(rows[0].sandboxAtBaseline, false);
  await assert.doesNotReject(() => lstat(join(f.locks, "fireemu-oracle-sbx.lock")));
});

test("calendar recovery refuses each original proof mismatch before reservation or credentials", async (t) => {
  for (const overrides of [
    { originalPacketSha256: "9".repeat(64) },
    { originalJournalSha256: "9".repeat(64) },
    { originalLedgerRowSha256: "9".repeat(64) },
    { originalSourceCommit: "9".repeat(40) },
    { originalHarnessDigest: "9".repeat(64) },
    { originalCorpusDigest: "9".repeat(64) },
    { originalRequests: 2 },
    { originalRequests: null },
    { maxDeleteAttemptsPerJob: 4 },
  ]) {
    const f = await recoveryFixture(t),
      before = await readFile(f.ledger, "utf8");
    await f.reset(overrides, "SCHEDULED-FUNCTIONS calendar recovery packet");
    await assert.rejects(captureCalendarRecovery(f.options), /original|recovery|binding|packet/);
    assert.equal(f.counts().tokens, 0);
    assert.equal(f.options.sendCount, undefined);
    assert.equal(await readFile(f.ledger, "utf8"), before);
  }
});

test("calendar recovery verifies actual journal count and requests rather than only their supplied hashes", async (t) => {
  for (const kind of ["count", "foreign-route", "duplicate-id", "unowned-extra", "schema"]) {
    const f = await recoveryFixture(t),
      folder = join(f.lane, "calendar-" + f.plan.originalRunId),
      journalPath = join(folder, "requests.jsonl");
    let row = JSON.parse((await readFile(f.ledger, "utf8")).trim()),
      journal = await readFile(journalPath, "utf8"),
      originalRequests = 1;
    if (kind === "count") {
      originalRequests = 2;
      row.requests = 2;
    }
    if (kind === "foreign-route") {
      const entry = JSON.parse(journal);
      entry.url =
        "https://cloudscheduler.googleapis.com/v1/projects/foreign/locations/us-central1/jobs/foreign";
      journal = JSON.stringify(entry) + "\n";
    }
    if (kind === "duplicate-id") {
      journal += journal;
      originalRequests = 2;
      row.requests = 2;
    }
    if (kind === "unowned-extra") {
      const entry = JSON.parse(journal);
      entry.id = "c99-delete-retry-1";
      journal = JSON.stringify(entry) + "\n";
    }
    if (kind === "schema") {
      const raw = JSON.parse(await readFile(join(folder, "raw-packet.json"), "utf8"));
      raw.schemaVersion = 2;
      const bytes = JSON.stringify(raw);
      await writeFile(join(folder, "raw-packet.json"), bytes);
      row.packetSha256 = sha256(bytes);
    }
    await writeFile(journalPath, journal);
    const line = JSON.stringify(row);
    await writeFile(f.ledger, line + "\n");
    await f.reset(
      {
        originalRequests,
        originalPacketSha256: row.packetSha256,
        originalJournalSha256: sha256(journal),
        originalLedgerRowSha256: sha256(line),
      },
      "SCHEDULED-FUNCTIONS calendar recovery packet",
    );
    await assert.rejects(
      captureCalendarRecovery(f.options),
      /original.*(count|binding|packet|journal)/,
    );
    assert.equal(f.counts().tokens, 0);
    assert.equal(f.options.sendCount, undefined);
  }
});

test("calendar recovery rejects newer sandbox activity, closed original, spacing and an independently open sibling", async (t) => {
  for (const kind of ["newer", "closed", "spacing", "sibling", "budget"]) {
    const f = await recoveryFixture(t);
    let row = JSON.parse((await readFile(f.ledger, "utf8")).trim()),
      other;
    if (kind === "closed") {
      row.event = "cleanup-verified";
      row.sandboxAtBaseline = true;
      delete row.outcome;
    }
    if (kind === "spacing") row.ts = "2026-09-30T08:31:00Z";
    if (kind === "newer")
      other = {
        project: f.plan.project,
        taskId: "OTHER",
        attemptId: "other",
        ts: "2026-09-30T08:05:00Z",
        event: "finished",
        sandboxAtBaseline: true,
      };
    if (kind === "sibling")
      other = {
        project: f.plan.project,
        taskId: "SCHEDULED-FUNCTIONS",
        attemptId: "9".repeat(16),
        ts: "2026-09-30T07:00:00Z",
        event: "needs-recovery",
        sandboxAtBaseline: false,
      };
    if (kind === "budget")
      other = {
        project: "other-project",
        taskId: "SCHEDULED-FUNCTIONS",
        attemptId: "budget",
        ts: "2026-09-29T07:00:00Z",
        event: "finished",
        sandboxAtBaseline: true,
        estimatedUsd: 10,
      };
    const line = JSON.stringify(row),
      before = line + "\n" + (other ? JSON.stringify(other) + "\n" : "");
    await writeFile(f.ledger, before);
    await f.reset(
      { originalLedgerRowSha256: sha256(line) },
      "SCHEDULED-FUNCTIONS calendar recovery packet",
    );
    await assert.rejects(
      captureCalendarRecovery(f.options),
      /original|spacing|newer|admission|budget/,
    );
    assert.equal(f.counts().tokens, 0);
    assert.equal(f.options.sendCount, undefined);
    assert.equal(await readFile(f.ledger, "utf8"), before);
  }
});

test("calendar recovery refuses appended original-attempt closure without packet linkage", async (t) => {
  for (const ts of ["2026-09-30T08:00:00Z", "2026-09-30T07:00:00Z"]) {
    const f = await recoveryFixture(t);
    const before =
      (await readFile(f.ledger, "utf8")) +
      JSON.stringify({
        project: f.plan.project,
        taskId: "SCHEDULED-FUNCTIONS",
        attemptId: f.plan.originalRunId,
        event: "cleanup-verified",
        sandboxAtBaseline: true,
        ts,
      }) +
      "\n";
    await writeFile(f.ledger, before);
    await assert.rejects(
      captureCalendarRecovery(f.options),
      /original recovery ledger proof differs/,
    );
    assert.deepEqual(f.counts(), { tokens: 0, sends: 0 });
    assert.equal(await readFile(f.ledger, "utf8"), before);
    await assert.rejects(lstat(join(f.locks, "fireemu-oracle-sbx.lock")), { code: "ENOENT" });
  }
});

test("calendar recovery rejects changed rawpacket bytes even when parsed metadata still matches", async (t) => {
  const f = await recoveryFixture(t);
  const path = join(f.lane, "calendar-" + f.plan.originalRunId, "raw-packet.json");
  const bytes = await readFile(path);
  await writeFile(path, Buffer.concat([bytes, Buffer.from(" ")]));
  await assert.rejects(captureCalendarRecovery(f.options), /original recovery packet differs/);
  assert.equal(f.counts().tokens, 0);
  assert.equal(f.options.sendCount, undefined);
});

test("calendar recovery binds journals that continue after one or two400 CREATE refusals", async (t) => {
  for (const refused of [["c07"], ["c04", "c07"]]) {
    const f = await recoveryFixture(t);
    const templates = calendarRequests(
      f.plan.originalRunId,
      f.plan.projectNumber,
      Date.parse("2026-09-30T08:00:00Z"),
    );
    const dispatched = templates.filter(
      (r) =>
        !refused.some((id) => [id + "-pause", id + "-read-paused", id + "-delete"].includes(r.id)),
    );
    const journal =
      dispatched
        .flatMap((r) => {
          const rows = [{ ...r, state: "before-send", dispatchAt: "2026-09-30T08:00:00Z" }];
          if (refused.some((id) => r.id === id + "-create"))
            rows.push({ id: r.id, state: "response-persisted", status: 400 });
          return rows;
        })
        .map(JSON.stringify)
        .join("\n") + "\n";
    const row = JSON.parse((await readFile(f.ledger, "utf8")).trim());
    row.requests = dispatched.length;
    const line = JSON.stringify(row);
    await writeFile(join(f.lane, "calendar-" + f.plan.originalRunId, "requests.jsonl"), journal, {
      mode: 0o600,
    });
    await writeFile(f.ledger, line + "\n");
    await f.reset(
      {
        originalRequests: dispatched.length,
        originalJournalSha256: sha256(journal),
        originalLedgerRowSha256: sha256(line),
      },
      "SCHEDULED-FUNCTIONS calendar recovery packet",
    );
    const result = await captureCalendarRecovery(f.options);
    assert.equal(f.counts().tokens, 1);
    assert.equal(dispatched.length, 61 - 3 * refused.length);
    assert.ok(dispatched.some((r) => r.id === "c08-create"));
    assert.equal(result.outcome, "calendar-recovery-needs-review");
    assert.equal(result.cleanupVerified, false);
  }
});

test("unsupported recovery scope or scope on a seed refuses before credentials", async (t) => {
  for (const kind of ["seed", "recovery"]) {
    const f = kind === "seed" ? await fixture(t) : await recoveryFixture(t);
    await f.reset(
      { recoveryScope: kind === "seed" ? "topic-only" : "unknown" },
      kind === "seed"
        ? "SCHEDULED-FUNCTIONS calendar seed packet"
        : "SCHEDULED-FUNCTIONS calendar recovery packet",
    );
    await assert.rejects(
      kind === "seed" ? captureCalendar(f.options) : captureCalendarRecovery(f.options),
      /scope/,
    );
    assert.equal(f.counts().tokens, 0);
  }
});

async function setTopicOnlyOriginal(f, jobMutation) {
  const specs = calendarRequests(
    f.plan.originalRunId,
    f.plan.projectNumber,
    Date.parse("2026-09-30T08:00:00Z"),
  );
  const sent = specs.filter((r) =>
    ["identity", "create-topic", ...(jobMutation ? [jobMutation] : [])].includes(r.id),
  );
  const journal =
    sent
      .flatMap((r) => [
        { ...r, state: "before-send", dispatchAt: "2026-09-30T08:00:00Z" },
        ...(r.id === "c01-create" ? [{ id: r.id, state: "response-persisted", status: 400 }] : []),
      ])
      .map(JSON.stringify)
      .join("\n") + "\n";
  const row = JSON.parse((await readFile(f.ledger, "utf8")).trim());
  row.requests = sent.length;
  const line = JSON.stringify(row);
  await writeFile(join(f.lane, "calendar-" + f.plan.originalRunId, "requests.jsonl"), journal);
  await writeFile(f.ledger, line + "\n");
  await f.reset(
    {
      recoveryScope: "topic-only",
      originalRequests: sent.length,
      originalJournalSha256: sha256(journal),
      originalLedgerRowSha256: sha256(line),
    },
    "SCHEDULED-FUNCTIONS calendar recovery packet",
  );
  f.options.sleep = async () => {};
}

test("topic-only recovery rejects any dispatched original job mutation even if refused400", async (t) => {
  for (const id of ["c01-create", "c01-pause", "c01-delete"]) {
    const f = await recoveryFixture(t);
    await setTopicOnlyOriginal(f, id);
    await assert.rejects(captureCalendarRecovery(f.options), /topic.only|scope|original.*mutation/);
    assert.equal(f.counts().tokens, 0);
    assert.equal(f.options.sendCount, undefined);
  }
});

test("topic-only recovery admits a hash-bound topic intent with zero original job writes", async (t) => {
  const f = await recoveryFixture(t);
  await setTopicOnlyOriginal(f);
  const result = await captureCalendarRecovery(f.options);
  assert.equal(f.counts().tokens, 1);
  assert.ok(result.attempted <= 9);
  assert.equal(result.cleanupVerified, false);
});

async function rebindOriginalJournal(f, rows) {
  const journal = rows.map(JSON.stringify).join("\n") + "\n";
  const row = JSON.parse((await readFile(f.ledger, "utf8")).trim());
  row.requests = rows.filter((r) => r.state === "before-send").length;
  const line = JSON.stringify(row);
  await writeFile(join(f.lane, "calendar-" + f.plan.originalRunId, "requests.jsonl"), journal);
  await writeFile(f.ledger, line + "\n");
  await f.reset(
    {
      originalRequests: row.requests,
      originalJournalSha256: sha256(journal),
      originalLedgerRowSha256: sha256(line),
    },
    "SCHEDULED-FUNCTIONS calendar recovery packet",
  );
}

test("topic-only admission binds new poll routes and deadline metadata with a shared three-extra cap", async (t) => {
  for (const fault of [null, "fourth-extra", "wrong-poll-route", "wrong-deadline"]) {
    const f = await recoveryFixture(t);
    await setTopicOnlyOriginal(f);
    const rows = (
      await readFile(join(f.lane, "calendar-" + f.plan.originalRunId, "requests.jsonl"), "utf8")
    )
      .trim()
      .split("\n")
      .map(JSON.parse);
    const templates = calendarRequests(
      f.plan.originalRunId,
      f.plan.projectNumber,
      Date.parse("2026-09-30T08:00:00Z"),
    );
    const topicRead = templates.find((r) => r.id === "read-topic");
    for (let n = 1; n <= 3; n++)
      rows.push({
        ...topicRead,
        id: "read-topic-poll-" + n,
        timeoutMs: 10000,
        state: "before-send",
        dispatchAt: "2026-09-30T08:00:00Z",
      });
    if (fault === "fourth-extra")
      rows.push({
        ...templates.find((r) => r.id === "c01-read-paused"),
        id: "c01-read-before-pause",
        state: "before-send",
        dispatchAt: "2026-09-30T08:00:00Z",
      });
    if (fault === "wrong-poll-route") rows.at(-1).url += "-foreign";
    if (fault === "wrong-deadline") rows.find((r) => r.id === "create-topic").timeoutMs = 10000;
    await rebindOriginalJournal(f, rows);
    if (fault) {
      await assert.rejects(captureCalendarRecovery(f.options), /journal.*(binding|budget)/);
      assert.equal(f.counts().tokens, 0);
      assert.equal(f.options.sendCount, undefined);
    } else {
      const result = await captureCalendarRecovery(f.options);
      assert.equal(f.counts().tokens, 1);
      assert.ok(result.attempted <= 9);
      assert.equal(result.cleanupVerified, false);
    }
  }
});

test("topic-only admission refuses an original with no topic PUT intent", async (t) => {
  const f = await recoveryFixture(t);
  f.options.sleep = async () => {};
  await f.reset({ recoveryScope: "topic-only" }, "SCHEDULED-FUNCTIONS calendar recovery packet");
  await assert.rejects(captureCalendarRecovery(f.options), /topic.only.*scope/);
  assert.equal(f.counts().tokens, 0);
  assert.equal(f.options.sendCount, undefined);
});

test("recovery journal admission accepts30second job CREATE metadata and rejects it on another route", async (t) => {
  for (const fault of [null, "create10", "read30"]) {
    const f = await recoveryFixture(t);
    const specs = calendarRequests(
      f.plan.originalRunId,
      f.plan.projectNumber,
      Date.parse("2026-09-30T08:00:00Z"),
    );
    const spec = specs.find(
      (r) => r.id === (fault === "read30" ? "c01-read-paused" : "c01-create"),
    );
    const rows = [
      {
        ...spec,
        timeoutMs: fault === "create10" ? 10000 : 30000,
        state: "before-send",
        dispatchAt: "2026-09-30T08:00:00Z",
      },
    ];
    await rebindOriginalJournal(f, rows);
    if (fault) {
      await assert.rejects(captureCalendarRecovery(f.options), /journal request binding/);
      assert.equal(f.counts().tokens, 0);
      assert.equal(f.options.sendCount, undefined);
    } else {
      const result = await captureCalendarRecovery(f.options);
      assert.equal(f.counts().tokens, 1);
      assert.equal(result.cleanupVerified, false);
    }
  }
});

async function settledRecoveryFixture(t, alter = () => {}) {
  const { fixture: journalFixture, recoveryEnvironment } =
    await import("./calendar-settled-topic.test.mjs");
  const f = await recoveryFixture(t),
    folder = join(f.lane, "calendar-" + f.plan.originalRunId);
  const rows = journalFixture();
  alter(rows);
  const journal = rows.map(JSON.stringify).join("\n") + "\n";
  await writeFile(join(folder, "requests.jsonl"), journal, { mode: 0o600 });
  const originalRow = JSON.parse((await readFile(f.ledger, "utf8")).trim());
  originalRow.requests = rows.filter((r) => r.state === "before-send").length;
  originalRow.ts = "2026-10-01T05:01:01.000Z";
  const line = JSON.stringify(originalRow);
  await writeFile(f.ledger, line + "\n");
  await f.reset(
    {
      recoveryScope: "settled-jobs-topic-only",
      originalRequests: originalRow.requests,
      originalJournalSha256: sha256(journal),
      originalLedgerRowSha256: sha256(line),
    },
    "SCHEDULED-FUNCTIONS calendar recovery packet",
  );
  const environment = recoveryEnvironment();
  f.options.clock = () => new Date("2026-10-01T06:00:00.000Z");
  f.options.send = environment.deps.send;
  f.options.sleep = environment.deps.sleep;
  return { ...f, environment };
}
test("settled-topic actual-group admission completes before credentials and retains both debts after one topic write", async (t) => {
  const f = await settledRecoveryFixture(t);
  const summary = await captureCalendarRecovery(f.options);
  assert.equal(summary.closureReady, true);
  assert.equal(summary.cleanupVerified, false);
  assert.equal(summary.attempted, 8);
  assert.equal(f.counts().tokens, 1);
  assert.equal(f.environment.sends.filter((r) => r.method !== "GET").length, 1);
  const rows = (await readFile(f.ledger, "utf8")).trim().split("\n").map(JSON.parse);
  assert.equal(rows.length, 3);
  assert.equal(rows.at(-1).event, "needs-recovery");
  assert.equal(rows[0].sandboxAtBaseline, false);
});
test("settled-topic admission refuses each incompletely settled or ambiguous original before reservation and credentials", async (t) => {
  for (const kind of [
    "missing",
    "body-unknown",
    "duplicate",
    "foreign-body",
    "sub200",
    "redirect",
    "server-error",
    "bad-deadline",
    "end-time",
  ]) {
    const f = await settledRecoveryFixture(t, (rows) => {
      const index = rows.findIndex((r) => r.id === "c01-create" && r.state === "before-send");
      if (kind === "missing") rows.splice(index + 2, 1);
      else if (kind === "body-unknown") rows[index + 2].state = "body-unknown";
      else if (kind === "duplicate") rows.splice(index + 1, 0, { ...rows[index + 1] });
      else if (kind === "foreign-body") {
        const body = Buffer.from(rows[index + 2].bodyBase64, "base64")
          .toString()
          .replace(/-c01/g, "-c02");
        rows[index + 2].bodyBase64 = Buffer.from(body).toString("base64");
      } else if (kind === "bad-deadline") rows[index].timeoutMs = 10000;
      else if (kind === "end-time") rows.at(-1).responseAt = "2026-10-01T05:02:00.000Z";
      else {
        rows[index + 1].status = rows[index + 2].status = {
          sub200: 199,
          redirect: 302,
          "server-error": 503,
        }[kind];
      }
    });
    const before = await readFile(f.ledger, "utf8");
    await assert.rejects(captureCalendarRecovery(f.options), /proof differs|binding|time differs/);
    assert.equal(f.counts().tokens, 0);
    assert.equal(f.environment.sends.length, 0);
    assert.equal(await readFile(f.ledger, "utf8"), before);
  }
});
test("old topic-only scope remains unable to admit settled journal with any original job mutation", async (t) => {
  const f = await settledRecoveryFixture(t);
  await f.reset({ recoveryScope: "topic-only" }, "SCHEDULED-FUNCTIONS calendar recovery packet");
  await assert.rejects(captureCalendarRecovery(f.options), /topic-only original scope/);
  assert.equal(f.counts().tokens, 0);
  assert.equal(f.environment.sends.length, 0);
});
