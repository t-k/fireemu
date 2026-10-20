// The sandbox runner's recording loop (fs-query-index/run.mjs) and its run-close check for
// unknown rows (fs-query-index/unknown-rows.mjs). Nothing here sends a request.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { LANES } from "./fs-query-index/lanes.mjs";
import * as run from "./fs-query-index/run.mjs";
import { UNKNOWN_ROW_PATTERN, isUnknownRow, unknownRows } from "./fs-query-index/unknown-rows.mjs";

const lane = LANES["fs-ent-pipeline"];
const programs = [
  { id: "fs-ent-pipeline/t/a", seed: [], steps: [{ id: "s1" }, { id: "s2" }] },
  { id: "fs-ent-pipeline/t/b", seed: [], steps: [{ id: "s1" }] },
  { id: "fs-ent-pipeline/t/c", seed: [], steps: [{ id: "s1" }] },
];
const meta = { harness: "h", startedAt: "2026-10-20T00:00:00Z", sha: "s" };
const rows = (program, marker) => ({
  steps: Object.fromEntries(program.steps.map((s) => [s.id, { status: 200, body: [{ marker }] }])),
  raw: Object.fromEntries(program.steps.map((s) => [s.id, { request: "raw" }])),
});
const recording = (marker, upTo = programs.length) => ({
  context: { run: marker, startedMs: 0 },
  results: Object.fromEntries(programs.slice(0, upTo).map((p) => [p.id, rows(p, marker)])),
  failures: [],
  requests: upTo,
  harnessRequests: 1,
});
/** A fatal error as runCorpus throws it: the programs that finished ride along as `partial`. */
const fatal = (marker, upTo) =>
  Object.assign(new Error("harness seed answered 400"), {
    fatal: true,
    partial: (({ context: _context, ...rest }) => rest)(recording(marker, upTo)),
  });

async function withDir(body) {
  const dir = await mkdtemp(join(tmpdir(), "fs-query-index-recorder-"));
  try {
    return await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("a complete run saves both recordings and nothing partial", () =>
  withDir(async (runDir) => {
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      secrets: () => [],
      record: async (n) => recording(String(n)),
    });
    assert.equal(out.outcome, "recorded");
    assert.equal(out.error, undefined);
    assert.equal(out.recordings.length, 2);
    for (const n of [1, 2]) {
      const saved = JSON.parse(await readFile(join(runDir, `recording-${n}.json`), "utf8"));
      assert.deepEqual(saved, recording(String(n - 1)));
    }
    assert.equal(existsSync(join(runDir, "fixture.partial.json")), false);
    assert.equal(out.partial, undefined);
  }));

test("a fatal error in the second recording keeps its finished programs and a readable fixture", () =>
  withDir(async (runDir) => {
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      secrets: () => [],
      record: async (n) => {
        if (n === 1) throw fatal("1", 1);
        return recording("0");
      },
    });
    assert.equal(out.outcome, "aborted-fatal");
    assert.match(out.error, /harness seed answered 400/);
    // The ledger counts the partial recording's requests too.
    assert.equal(out.recordings.length, 2);
    const partial = JSON.parse(await readFile(join(runDir, "recording-2.partial.json"), "utf8"));
    assert.deepEqual(Object.keys(partial.results), [programs[0].id]);
    assert.equal(existsSync(join(runDir, "recording-2.json")), false);
    assert.equal((await stat(join(runDir, "recording-2.partial.json"))).mode & 0o777, 0o600);

    const fixturePath = join(runDir, "fixture.partial.json");
    assert.equal((await stat(fixturePath)).mode & 0o777, 0o600);
    const fixture = JSON.parse(await readFile(fixturePath, "utf8"));
    assert.equal(fixture.partial, true);
    assert.equal(fixture.outcome, "aborted-fatal");
    assert.equal(fixture.recordedAgainst.target, lane.target);
    // Every program either recording finished, with the number of recordings that hold it.
    assert.deepEqual(
      Object.fromEntries(Object.entries(fixture.programs).map(([id, p]) => [id, p.recordings])),
      { [programs[0].id]: 2, [programs[1].id]: 1, [programs[2].id]: 1 },
    );
    const first = fixture.programs[programs[0].id];
    assert.deepEqual(first.steps, rows(programs[0], "0").steps);
    // The rows that differed between the two recordings are kept as `second`.
    assert.deepEqual(first.second, rows(programs[0], "1").steps);
    assert.equal(fixture.programs[programs[1].id].second, undefined);
    assert.equal(first.corpusDigest, run.programDigest(programs[0]));
    assert.equal(first.harnessDigest, "h");
    // The raw requests stay in the private recordings only.
    assert.equal(JSON.stringify(fixture).includes('"raw"'), false);
    assert.deepEqual(out.partial, {
      file: "recording-2.partial.json",
      fixture: "fixture.partial.json",
      programs: programs.map((p) => p.id),
    });
  }));

test("a fatal error in the first recording keeps the programs it finished", () =>
  withDir(async (runDir) => {
    let calls = 0;
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      secrets: () => [],
      record: async () => {
        calls += 1;
        throw fatal("0", 2);
      },
    });
    // The second recording never starts after a fatal error.
    assert.equal(calls, 1);
    assert.equal(out.outcome, "aborted-fatal");
    assert.equal(existsSync(join(runDir, "recording-1.json")), false);
    const partial = JSON.parse(await readFile(join(runDir, "recording-1.partial.json"), "utf8"));
    assert.deepEqual(Object.keys(partial.results), [programs[0].id, programs[1].id]);
    const fixture = JSON.parse(await readFile(join(runDir, "fixture.partial.json"), "utf8"));
    assert.deepEqual(Object.keys(fixture.programs), [programs[0].id, programs[1].id]);
    assert.equal(fixture.programs[programs[0].id].recordings, 1);
  }));

test("an error without a partial recording (a preflight refusal) writes no partial files", () =>
  withDir(async (runDir) => {
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      secrets: () => [],
      preflightCheck: async () => {
        throw new Error("entpipe1 is not empty");
      },
      record: async () => assert.fail("no recording after a refused preflight"),
    });
    assert.equal(out.outcome, "aborted");
    assert.match(out.error, /not empty/);
    assert.deepEqual(out.recordings, []);
    assert.equal(existsSync(join(runDir, "fixture.partial.json")), false);
    assert.equal(existsSync(join(runDir, "recording-1.partial.json")), false);
  }));

test("a partial fixture that leaks a private value is refused, and the partial recording is kept", () =>
  withDir(async (runDir) => {
    const token = "ya29.secret-token-value-0123456789";
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      // The token of the recording is known only after it started.
      secrets: () => ["fireemu-oracle-query"],
      record: async () => {
        throw fatal(`projects/fireemu-oracle-query ${token}`, 1);
      },
    });
    assert.equal(out.outcome, "aborted-fatal");
    assert.match(out.error, /harness seed answered 400/);
    assert.match(out.error, /partial fixture not written: fixture contains an access token/);
    assert.equal(existsSync(join(runDir, "recording-1.partial.json")), true);
    assert.equal(existsSync(join(runDir, "fixture.partial.json")), false);
    assert.equal(out.partial.fixture, undefined);
  }));

test("a non-fatal error that carries a partial recording ends as aborted and keeps it", () =>
  withDir(async (runDir) => {
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      secrets: () => [],
      record: async () => {
        const error = fatal("0", 1);
        error.fatal = false;
        throw error;
      },
    });
    assert.equal(out.outcome, "aborted");
    assert.equal(existsSync(join(runDir, "recording-1.partial.json")), true);
  }));

// --- unknown rows: the run-close check of the S3 log ---

const definiteHttp = (status) =>
  (status >= 200 && status <= 299) || (status >= 400 && status <= 499 && status !== 429);
const DEFINITE_GRPC = new Set([0, 3, 5, 6, 7, 9, 10, 11, 12, 16]);

test("every HTTP status but a 2xx or a 4xx other than 429 is an unknown row", () => {
  for (let status = -3; status <= 1200; status += 1) {
    const line = `fs-ent-pipeline/o4/stages#select-empty ${status}`;
    assert.equal(isUnknownRow(line), !definiteHttp(status), line);
  }
  for (const status of [0, -1, 100, 103, 199, 301, 302, 304, 399, 429, 500, 503, 599]) {
    assert.equal(isUnknownRow(`p/a/b#s ${status}`), true, String(status));
  }
});

test("a gRPC row is unknown unless its code settles the outcome", () => {
  for (let code = -3; code <= 120; code += 1) {
    const line = `fs-ent-pipeline/o1/kinds#select-grpc grpc ${code}`;
    assert.equal(isUnknownRow(line), !DEFINITE_GRPC.has(code), line);
  }
  // The O-4 grep's classes stay unknown.
  for (const code of [-1, 4, 8, 13, 14]) assert.equal(isUnknownRow(`p#s grpc ${code}`), true);
});

test("the grep -E pattern the after-steps quote says the same as the check", () => {
  const pattern = new RegExp(UNKNOWN_ROW_PATTERN);
  const lines = [];
  for (let status = -12; status <= 1200; status += 1) lines.push(`p/a/b#s-1 ${status}`);
  for (let code = -12; code <= 120; code += 1) lines.push(`p/a/b#s-1 grpc ${code}`);
  // A log prefix before the step and text after the status.
  for (const status of [200, 404, 429, 500]) {
    lines.push(`2026-10-20T00:00:00Z p/a/b#s ${status}`, `p/a/b#s ${status} extra`);
  }
  for (const line of lines) assert.equal(pattern.test(line), isUnknownRow(line), line);
  assert.equal(isUnknownRow("2026-10-20T00:00:00Z p/a/b#s 500"), true);
  assert.equal(isUnknownRow("p/a/b#s 500 extra"), false);
  // POSIX ERE has no \d, lazy quantifier or lookahead.
  assert.doesNotMatch(UNKNOWN_ROW_PATTERN, /\\d|\*\?|\(\?/);
});

test("only step lines count: the summary, the ledger echo and other log lines never do", () => {
  const log = [
    "fs-ent-pipeline/o4/aliases#plain 200",
    "fs-ent-pipeline/o4/aliases#syntax 400",
    "fs-ent-pipeline/o4/documents#write-a 503",
    "{",
    '  "requests": 242,',
    "fs-ent-pipeline/o4/documents#get-a 302",
    "HTTP 500 from the token endpoint",
    "fs-ent-pipeline/o4/stages#x 200 extra",
    "fs-ent-pipeline/o4/stages#y grpc 14",
    "",
  ].join("\n");
  assert.deepEqual(unknownRows(log), [
    { line: 3, text: "fs-ent-pipeline/o4/documents#write-a 503" },
    { line: 6, text: "fs-ent-pipeline/o4/documents#get-a 302" },
    { line: 9, text: "fs-ent-pipeline/o4/stages#y grpc 14" },
  ]);
  assert.deepEqual(unknownRows("p#s 200\r\np#t 500\r\n"), [{ line: 2, text: "p#t 500" }]);
});
