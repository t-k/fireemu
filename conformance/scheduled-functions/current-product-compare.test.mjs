import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CALENDAR_CASES, calendarRequests } from "./calendar.mjs";

const module = await import("./current-product-compare.mjs").catch(() => ({}));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "calendar-current-product-"));
  t.after(() => rm(root, { recursive: true }));
  const directory = join(root, "recording");
  await mkdir(directory, { mode: 0o700 });
  for (const [name, version] of [
    ["firebase-functions", "7.3.2"],
    ["firebase-tools", "15.28.2"],
  ]) {
    const path = join(root, "conformance/node_modules", name);
    await mkdir(path, { recursive: true });
    await writeFile(join(path, "package.json"), JSON.stringify({ version }));
  }
  const binary = join(root, "binary"),
    runner = join(root, "runner");
  await writeFile(binary, "bound installed binary");
  await writeFile(runner, "bound installed runner");
  const corpus = readFileSync(new URL("./calendar-cases.json", import.meta.url));
  const packet = {
    schemaVersion: 1,
    kind: "calendar-seed",
    project: "fireemu-oracle-sbx",
    runId: "a1".repeat(8),
    projectNumber: "123456789012",
    sourceCommit: "b".repeat(40),
    harnessDigest: "c".repeat(64),
    corpusDigest: sha(corpus),
    maxRequests: 64,
    maxExtraRequests: 3,
    reserveUsd: 0.25,
  };
  const rows = CALENDAR_CASES.flatMap(({ id }) => {
    const spec = calendarRequests(
      packet.runId,
      packet.projectNumber,
      Date.parse("2026-09-30T16:00:01Z"),
    ).find((row) => row.id === id + "-create");
    const status = id < "c07" ? 200 : 400;
    const bytes = Buffer.from(
      JSON.stringify(
        status === 200
          ? { ...spec.json, state: "ENABLED", scheduleTime: "2026-10-01T00:00:00Z" }
          : {
              error: { code: 400, status: "INVALID_ARGUMENT", message: "recorded fixture refusal" },
            },
      ),
    );
    return [
      { ...spec, state: "before-send", dispatchAt: "2026-09-30T16:00:01Z" },
      { id: spec.id, state: "response-headers", status, responseAt: "2026-09-30T16:00:02Z" },
      {
        id: spec.id,
        state: "response-persisted",
        status,
        dispatchAt: "2026-09-30T16:00:01Z",
        responseAt: "2026-09-30T16:00:03Z",
        bodyBase64: bytes.toString("base64"),
        bodyBytes: bytes.length,
      },
    ];
  });
  const packetBytes = Buffer.from(JSON.stringify(packet)),
    journalBytes = Buffer.from(rows.map(JSON.stringify).join("\n") + "\n");
  await writeFile(join(directory, "raw-packet.json"), packetBytes, { mode: 0o600 });
  await writeFile(join(directory, "requests.jsonl"), journalBytes, { mode: 0o600 });
  const recording = {
    lane: root,
    directory,
    pins: {
      packetSha256: sha(packetBytes),
      journalSha256: sha(journalBytes),
      corpusSha256: sha(corpus),
      harnessSha256: packet.harnessDigest,
      sourceCommit: packet.sourceCommit,
      runId: packet.runId,
    },
  };
  const artifact = {
    root,
    binary,
    runner,
    binarySha256: sha("bound installed binary"),
    runnerSha256: sha("bound installed runner"),
    sourceCommit: "d".repeat(40),
    childPath: join(root, "calendar-child.mjs"),
  };
  const saved = [],
    calls = [];
  const executeSession = async ({ prepared, classification }) => {
    const { input, anchor } = JSON.parse(readFileSync(prepared.inputPath));
    calls.push({ input, anchor, classification });
    return {
      identity: prepared.identity,
      exitCode: classification === "accepted" ? 0 : 1,
      timedOut: false,
      cancelled: false,
      cleanup: { survivors: [], claims: [], listeners: [] },
      callback:
        classification === "accepted"
          ? {
              matched: true,
              reason: null,
              anchor,
              scheduleTime: input.scheduleTime,
              receipts: [{ sequence: 1, scheduleTime: input.scheduleTime }],
            }
          : undefined,
      diagnostic:
        classification === "observed-refusal"
          ? module.calendarRefusalDiagnostic(input.caseId)
          : undefined,
    };
  };
  return {
    recording,
    artifact,
    executeSession,
    save: async (row) => saved.push(row),
    saved,
    calls,
  };
}

test("compares all eight recorded cases with both accepted anchors and separate startup refusals", async (t) => {
  assert.equal(
    typeof module.compareRecordedCalendar,
    "function",
    "the installed case driver is missing",
  );
  const f = await fixture(t);
  const result = await module.compareRecordedCalendar(f);
  assert.equal(result.matched, 8);
  assert.equal(result.acceptedMatched, 6);
  assert.equal(result.refusalMatched, 2);
  assert.equal(f.calls.length, 14);
  assert.equal(f.saved.length, 8);
  assert.equal(result.fullClosure, false);
  assert.equal(result.nativeCertificateIssued, false);
  assert.deepEqual(
    result.rows.map((row) => row.caseId),
    CALENDAR_CASES.map((row) => row.id),
  );
  assert.ok(
    result.rows.every(
      (row) =>
        row.status === "MATCH" &&
        row.recording.runId === f.recording.pins.runId &&
        row.artifact.sourceCommit === f.artifact.sourceCommit,
    ),
  );
});

test("missing or malformed session proof stays needs-review instead of aborting independent cases", async (t) => {
  const f = await fixture(t),
    execute = f.executeSession;
  f.executeSession = async (options) => {
    const result = await execute(options);
    if (JSON.parse(readFileSync(options.prepared.inputPath)).input.caseId === "c01")
      delete result.callback.receipts[0].scheduleTime;
    return result;
  };
  const result = await module.compareRecordedCalendar(f);
  assert.equal(result.rows[0].status, "NEEDS_REVIEW");
  assert.equal(result.matched, 7);
  assert.equal(f.saved.length, 8);
});

test("every artifact, anchor, receipt, diagnostic and cleanup near miss fails closed", async (t) => {
  const mutations = [
    (s) => {
      s.identity = { ...s.identity, sourceCommit: "e".repeat(40) };
    },
    (s) => {
      s.exitCode = 2;
    },
    (s) => {
      s.cleanup.survivors.push({ pid: 123 });
    },
    (s) => {
      s.cleanup.claims.push({ port: 23000 });
    },
    (s) => {
      s.cleanup.listeners.push({ pid: 123 });
    },
    (s) => {
      delete s.cleanup.claims;
    },
    (s) => {
      s.callback.matched = false;
    },
    (s) => {
      s.callback.anchor = "2026-09-30T16:00:04Z";
    },
    (s) => {
      s.callback.receipts.push({ ...s.callback.receipts[0] });
    },
    (s) => {
      s.callback.scheduleTime = "2026-10-01T00:01:00Z";
      s.callback.receipts[0].scheduleTime = s.callback.scheduleTime;
    },
    (s) => {
      s.callback.receipts[0].scheduleTime = "2026-10-01T00:01:00Z";
    },
  ];
  for (const change of mutations) {
    const f = await fixture(t),
      execute = f.executeSession;
    f.executeSession = async (options) => {
      const result = await execute(options);
      if (JSON.parse(readFileSync(options.prepared.inputPath)).input.caseId === "c01")
        change(result);
      return result;
    };
    assert.equal((await module.compareRecordedCalendar(f)).rows[0].status, "NEEDS_REVIEW");
  }
  const f = await fixture(t),
    execute = f.executeSession;
  f.executeSession = async (options) => {
    const result = await execute(options);
    if (result.diagnostic) result.diagnostic += " ";
    return result;
  };
  const result = await module.compareRecordedCalendar(f);
  assert.equal(result.refusalMatched, 0);
  assert.equal(result.acceptedMatched, 6);
});

test("generated shifts around the production instant never turn a different occurrence into MATCH", async (t) => {
  for (const shift of [-86400, -3600, -60, -1, 1, 60, 3600, 86400]) {
    const f = await fixture(t),
      execute = f.executeSession;
    f.executeSession = async (options) => {
      const result = await execute(options);
      if (result.callback) {
        result.callback.receipts[0].scheduleTime = new Date(
          Date.parse(result.callback.scheduleTime) + shift * 1000,
        ).toISOString();
      }
      return result;
    };
    const result = await module.compareRecordedCalendar(f);
    assert.equal(result.acceptedMatched, 0);
    assert.equal(result.refusalMatched, 2);
  }
});

test("production byte pins are checked before any local process can start", async (t) => {
  const f = await fixture(t);
  f.recording.pins.journalSha256 = "f".repeat(64);
  await assert.rejects(module.compareRecordedCalendar(f), /whole-byte/);
  assert.equal(f.calls.length, 0);
  assert.equal(f.saved.length, 0);
});

test("unrecorded and unresolved answers cannot acquire a local comparison session", async (t) => {
  const f = await fixture(t),
    path = join(f.recording.directory, "requests.jsonl");
  const rows = readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse)
    .filter((row) => row.id !== "c01-create");
  for (const row of rows) if (row.id === "c07-create" && row.status) row.status = 503;
  const bytes = Buffer.from(rows.map(JSON.stringify).join("\n") + "\n");
  await writeFile(path, bytes, { mode: 0o600 });
  f.recording.pins.journalSha256 = sha(bytes);
  const result = await module.compareRecordedCalendar(f);
  assert.equal(result.matched, 6);
  assert.equal(result.rows[0].classification, "unrecorded");
  assert.equal(result.rows[6].classification, "unresolved");
  assert.deepEqual(
    result.rows.filter((row) => row.status === "NEEDS_REVIEW").map((row) => row.sessions),
    [[], []],
  );
  assert.equal(f.calls.length, 11);
});

test("the prepared collector rejects a non-loopback endpoint before it can send", async (t) => {
  const f = await fixture(t),
    inputPath = join(f.recording.directory, "input.json");
  await writeFile(
    inputPath,
    JSON.stringify({
      input: { scheduleTime: "2026-10-01T00:00:00Z" },
      anchor: "2026-09-30T16:00:01Z",
    }),
  );
  await assert.rejects(
    module.collectPreparedCalendar({
      prepared: { inputPath },
      controlUrl: "https://cloudscheduler.googleapis.com/v1/",
      functionsHost: "127.0.0.1:23000",
      token: "local-only",
    }),
    /loopback/,
  );
  assert.throws(() => module.calendarRefusalDiagnostic("c01"), /unrecorded/);
});

test("one matching anchor cannot hide a disagreement at the other recorded anchor", async (t) => {
  const f = await fixture(t),
    execute = f.executeSession;
  f.executeSession = async (options) => {
    const result = await execute(options);
    if (
      JSON.parse(readFileSync(options.prepared.inputPath)).input.caseId === "c01" &&
      result.callback?.anchor.endsWith("02Z")
    )
      result.callback.matched = false;
    return result;
  };
  const result = await module.compareRecordedCalendar(f);
  assert.equal(result.rows[0].status, "NEEDS_REVIEW");
  assert.deepEqual(
    result.rows[0].sessions.map(({ matched }) => matched),
    [true, false],
  );
  assert.equal(result.rows[0].productionGap, "UNKNOWN");
  assert.equal(result.productionGap, "UNKNOWN");
  assert.equal(result.acceptedAnchorRule, "both-recorded-endpoints");
});

test("a private fixture workspace is distinct from the installed product source root", async (t) => {
  const f = await fixture(t);
  f.artifact.fixtureRoot = f.artifact.root;
  f.artifact.root = "/bound/product/source/root";
  const result = await module.compareRecordedCalendar(f);
  assert.equal(result.matched, 8);
  assert.equal(result.artifact.sourceRoot, "/bound/product/source/root");
  assert.equal(result.artifact.fixtureRoot, f.artifact.fixtureRoot);
  assert.ok(
    f.saved.every(
      (row) =>
        row.artifact.sourceRoot === "/bound/product/source/root" &&
        row.artifact.fixtureRoot === f.artifact.fixtureRoot,
    ),
  );
});

test("startup refusal diagnostics include the exact CLI prefix and recorded declaration", () => {
  assert.equal(
    module.calendarRefusalDiagnostic("c07"),
    'error: manifest: function "calendarProbe": time zone: unknown time zone "Invalid/Unknown"',
  );
  assert.equal(
    module.calendarRefusalDiagnostic("c08"),
    'error: manifest: function "calendarProbe": schedule: unrecognised schedule "0 0 0 1 4 *"',
  );
});

test("a timeout or cancellation never counts as a match after successful cleanup", async (t) => {
  for (const field of ["timedOut", "cancelled"]) {
    const f = await fixture(t),
      execute = f.executeSession;
    f.executeSession = async (options) => ({ ...(await execute(options)), [field]: true });
    assert.equal((await module.compareRecordedCalendar(f)).matched, 0);
  }
});
