import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { calendarRequests } from "./calendar.mjs";
import { mkdtemp, mkdir, writeFile, rm, symlink, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordedCalendarInputs, loadRecordedCalendarInputs } from "./calendar-recording.mjs";
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function fixture() {
  const corpusBytes = readFileSync(new URL("./calendar-cases.json", import.meta.url));
  const packet = {
    schemaVersion: 1,
    kind: "calendar-seed",
    project: "fireemu-oracle-sbx",
    runId: "a1".repeat(8),
    projectNumber: "123456789012",
    sourceCommit: "b".repeat(40),
    harnessDigest: "c".repeat(64),
    corpusDigest: sha(corpusBytes),
    maxRequests: 64,
    maxExtraRequests: 3,
    reserveUsd: 0.25,
  };
  const specs = calendarRequests(
    packet.runId,
    packet.projectNumber,
    Date.parse("2026-09-30T16:00:01Z"),
  );
  const rows = ["c01", "c07"].flatMap((id) => {
    const request = specs.find((s) => s.id === id + "-create");
    const bytes = Buffer.from(
      JSON.stringify(
        id === "c01"
          ? { ...request.json, state: "ENABLED", scheduleTime: "2026-09-30T16:01:00Z" }
          : { error: { code: 400, status: "INVALID_ARGUMENT", message: "recorded fixture only" } },
      ),
    );
    const status = id === "c01" ? 200 : 400;
    return [
      { ...request, state: "before-send", dispatchAt: "2026-09-30T16:00:01Z" },
      { id: request.id, state: "response-headers", status, responseAt: "2026-09-30T16:00:02Z" },
      {
        id: request.id,
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
  return {
    packetBytes,
    journalBytes,
    corpusBytes,
    pins: {
      packetSha256: sha(packetBytes),
      journalSha256: sha(journalBytes),
      corpusSha256: sha(corpusBytes),
      harnessSha256: packet.harnessDigest,
      sourceCommit: packet.sourceCommit,
      runId: packet.runId,
    },
  };
}
test("recorded calendar admission binds whole bytes and distinguishes accepted, observed refusal and unrecorded cases", () => {
  const result = recordedCalendarInputs(fixture());
  assert.equal(result.productionParity, false);
  assert.equal(result.cases.length, 8);
  assert.equal(result.cases[0].classification, "accepted");
  assert.equal(result.cases[0].input.scheduleTime, "2026-09-30T16:01:00Z");
  assert.equal(result.cases[6].classification, "observed-refusal");
  assert.equal(result.cases[6].status, 400);
  assert.match(result.cases[6].bodySha256, /^[a-f0-9]{64}$/);
  assert.equal(result.cases[1].classification, "unrecorded");
});
test("recorded calendar admission refuses packet, journal, corpus, source, helper and run pin changes", () => {
  for (const key of ["packetBytes", "journalBytes", "corpusBytes"]) {
    const f = fixture();
    f[key] = Buffer.concat([f[key], Buffer.from(" ")]);
    assert.throws(() => recordedCalendarInputs(f), /binding|digest/);
  }
  for (const key of ["sourceCommit", "harnessSha256", "runId"]) {
    const f = fixture();
    f.pins[key] = "f".repeat(key === "sourceCommit" ? 40 : key === "runId" ? 16 : 64);
    assert.throws(() => recordedCalendarInputs(f), /binding/);
  }
});
test("recorded calendar admission refuses pinned but foreign, duplicated or out-of-order request proof", () => {
  const changes = [
    (r) => (r[0].url += "-foreign"),
    (r) => (r[3].url += "-foreign"),
    (r) => r.push(r[0]),
    (r) => ([r[0], r[1]] = [r[1], r[0]]),
    (r) => r[5].bodyBytes++,
    (r) => (r[4].responseAt = "2026-09-30T15:00:00Z"),
  ];
  for (const change of changes) {
    const f = fixture(),
      rows = f.journalBytes.toString().trim().split("\n").map(JSON.parse);
    change(rows);
    f.journalBytes = Buffer.from(rows.map(JSON.stringify).join("\n"));
    f.pins.journalSha256 = sha(f.journalBytes);
    assert.throws(() => recordedCalendarInputs(f), /request|journal|proof|body/);
  }
});
test("recorded calendar admission retains unknown body and server error as unresolved observations", () => {
  for (const state of ["body-unknown", "server-error"]) {
    const f = fixture(),
      rows = f.journalBytes.toString().trim().split("\n").map(JSON.parse);
    if (state === "body-unknown") {
      rows[5].state = state;
      delete rows[5].bodyBase64;
      delete rows[5].bodyBytes;
    } else {
      rows[4].status = 503;
      rows[5].status = 503;
    }
    f.journalBytes = Buffer.from(rows.map(JSON.stringify).join("\n"));
    f.pins.journalSha256 = sha(f.journalBytes);
    assert.equal(recordedCalendarInputs(f).cases[6].classification, "unresolved");
  }
});

test("recorded calendar file admission reads only bounded private regular lane files", async (t) => {
  const lane = await mkdtemp(join(tmpdir(), "calendar-recorded-proof-"));
  t.after(() => rm(lane, { recursive: true }));
  const directory = join(lane, "own-recording");
  await mkdir(directory, { mode: 0o700 });
  const f = fixture();
  const packet = join(directory, "raw-packet.json"),
    journal = join(directory, "requests.jsonl");
  await writeFile(packet, f.packetBytes, { mode: 0o600 });
  await writeFile(journal, f.journalBytes, { mode: 0o600 });
  const options = { lane, directory, pins: f.pins };
  assert.equal((await loadRecordedCalendarInputs(options)).cases[0].classification, "accepted");
  await chmod(journal, 0o644);
  await assert.rejects(loadRecordedCalendarInputs(options), /private/);
  await chmod(journal, 0o600);
  await rm(journal);
  await symlink(packet, journal);
  await assert.rejects(loadRecordedCalendarInputs(options), /private|symbolic/);
  await rm(journal);
  await writeFile(journal, Buffer.alloc(16 * 1024 * 1024 + 1), { mode: 0o600 });
  await assert.rejects(loadRecordedCalendarInputs(options), /bound/);
  await assert.rejects(
    loadRecordedCalendarInputs({ ...options, lane: directory, directory: lane }),
    /lane/,
  );
});

test("recorded refusal journal preserves submillisecond ordering validation", () => {
  const f = fixture(),
    rows = f.journalBytes.toString().trim().split("\n").map(JSON.parse);
  rows[3].dispatchAt = "2026-09-30T16:00:01.000000900Z";
  rows[4].responseAt = "2026-09-30T16:00:01.000000100Z";
  rows[5].dispatchAt = rows[3].dispatchAt;
  f.journalBytes = Buffer.from(rows.map(JSON.stringify).join("\n"));
  f.pins.journalSha256 = sha(f.journalBytes);
  assert.throws(() => recordedCalendarInputs(f), /proof/);
});

test("unusable complete native200 retains its raw proof and independently usable cases", () => {
  const f = fixture(),
    rows = f.journalBytes.toString().trim().split("\n").map(JSON.parse);
  const body = JSON.parse(Buffer.from(rows[2].bodyBase64, "base64"));
  delete body.scheduleTime;
  const bytes = Buffer.from(JSON.stringify(body));
  rows[2].bodyBase64 = bytes.toString("base64");
  rows[2].bodyBytes = bytes.length;
  f.journalBytes = Buffer.from(rows.map(JSON.stringify).join("\n"));
  f.pins.journalSha256 = sha(f.journalBytes);
  const result = recordedCalendarInputs(f);
  assert.equal(result.cases[0].classification, "unresolved");
  assert.match(result.cases[0].reason, /calendar/);
  assert.equal(result.cases[0].bodySha256, sha(bytes));
  assert.equal(result.cases[6].classification, "observed-refusal");
});
