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
import { isStepLine, isUnknownRow, scanLog, unknownRows } from "./fs-query-index/unknown-rows.mjs";

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

test("a partial recording that cannot be written still returns the outcome for meta.json and the ledger", () =>
  withDir(async (runDir) => {
    const { writeFile } = await import("node:fs/promises");
    const out = await run.recordRecordings({
      programs,
      runDir,
      meta,
      lane,
      secrets: () => [],
      write: async (path, ...rest) => {
        if (/recording-\d\.partial\.json$/.test(String(path))) {
          throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
        }
        return writeFile(path, ...rest);
      },
      record: async (n) => {
        if (n === 1) throw fatal("1", 1);
        return recording("0");
      },
    });
    assert.equal(out.outcome, "aborted-fatal");
    assert.match(out.error, /harness seed answered 400/);
    assert.match(out.error, /partial recording not written: ENOSPC/);
    // The partial fixture is derived from the partial recording, so it is not written either.
    assert.doesNotMatch(out.error, /partial fixture/);
    // The partial recording still counts toward the ledger's requests.
    assert.equal(out.recordings.length, 2);
    assert.equal(existsSync(join(runDir, "recording-1.json")), true);
    assert.equal(existsSync(join(runDir, "recording-2.partial.json")), false);
    assert.equal(existsSync(join(runDir, "fixture.partial.json")), false);
    assert.equal(out.partial, undefined);
  }));

test("a partial fixture is never read as a committed one", () =>
  withDir(async (dir) => {
    const { writeFile } = await import("node:fs/promises");
    const base = { version: 1, recordedAgainst: {}, programs: {} };
    assert.doesNotThrow(() => run.assertCompleteFixture(base, "f.json"));
    assert.throws(
      () => run.assertCompleteFixture({ ...base, partial: true }, "f.json"),
      /f\.json is the partial fixture of a stopped run/,
    );
    assert.throws(
      () =>
        run.assertCompleteFixture(
          { ...base, programs: { [programs[0].id]: { steps: {}, recordings: 1 } } },
          "f.json",
        ),
      /f\.json is the partial fixture of a stopped run/,
    );
    // writeFixture refuses to merge into one.
    const fixturePath = join(dir, "fixture.json");
    await writeFile(fixturePath, JSON.stringify({ ...base, partial: true, outcome: "aborted" }));
    await assert.rejects(
      run.writeFixture({
        programs,
        recordings: [recording("0"), recording("0")],
        meta,
        secrets: [],
        lane,
        fixturePath,
      }),
      /partial fixture of a stopped run/,
    );
    // No committed lane fixture is partial (the Rust replay reads them directly).
    const { readFile: read } = await import("node:fs/promises");
    for (const each of Object.values(LANES)) {
      const path = new URL(`../${each.fixture}`, import.meta.url);
      if (!existsSync(path)) continue;
      run.assertCompleteFixture(JSON.parse(await read(path, "utf8")), each.fixture);
    }
  }));

test("meta.json that cannot be written is reported, never thrown, so the ledger row still lands", () =>
  withDir(async (runDir) => {
    const failing = async () => {
      throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
    };
    const meta1 = { ...meta, programs: [] };
    assert.equal(
      await run.writeMeta({ runDir, meta: meta1, outcome: "recorded", write: failing }),
      "meta.json not written: ENOSPC: no space left on device",
    );
    assert.equal(
      await run.writeMeta({
        runDir,
        meta: meta1,
        outcome: "aborted",
        error: "seed refused",
        write: failing,
      }),
      "seed refused (meta.json not written: ENOSPC: no space left on device)",
    );
    assert.equal(
      await run.writeMeta({ runDir, meta: meta1, outcome: "aborted", error: "seed refused" }),
      "seed refused",
    );
    const written = JSON.parse(await readFile(join(runDir, "meta.json"), "utf8"));
    assert.equal(written.outcome, "aborted");
    assert.equal(written.error, "seed refused");
    assert.equal((await stat(join(runDir, "meta.json"))).mode & 0o777, 0o600);
    assert.equal(await run.writeMeta({ runDir, meta: meta1, outcome: "recorded" }), undefined);
  }));

test("check, export-comparison and the request export read the committed fixture through the guard", () =>
  withDir(async (dir) => {
    const { writeFile } = await import("node:fs/promises");
    const { loadCommittedFixture } = await import("./fs-query-index/fixture-scan.mjs");
    const { recordedPrograms } = await import("./fs-ent-pipeline/export-requests.mjs");
    const complete = join(dir, "complete.json");
    const partial = join(dir, "partial.json");
    const once = join(dir, "once.json");
    const body = { version: 1, recordedAgainst: {}, programs: { [programs[0].id]: { steps: {} } } };
    await writeFile(complete, JSON.stringify(body));
    await writeFile(partial, JSON.stringify({ ...body, partial: true }));
    await writeFile(
      once,
      JSON.stringify({ ...body, programs: { [programs[0].id]: { steps: {}, recordings: 1 } } }),
    );
    const loaded = await loadCommittedFixture(complete);
    assert.deepEqual(loaded.fixture, body);
    assert.equal(loaded.text, JSON.stringify(body));
    for (const path of [partial, once]) {
      await assert.rejects(loadCommittedFixture(path), /partial fixture of a stopped run/);
      assert.throws(() => recordedPrograms(programs, path), /partial fixture of a stopped run/);
    }
    assert.deepEqual(
      recordedPrograms(programs, complete).map((p) => p.id),
      [programs[0].id],
    );
    // run.mjs reads through the same loader at both places.
    const source = await readFile(new URL("./fs-query-index/run.mjs", import.meta.url), "utf8");
    const checkBody = source.slice(source.indexOf("async function check()"));
    assert.match(checkBody.slice(0, 400), /loadCommittedFixture\(FIXTURE\)/);
    const exportBody = source.slice(source.indexOf("async function exportComparison("));
    assert.match(exportBody.slice(0, 400), /loadCommittedFixture\(FIXTURE\)/);
  }));

// --- unknown rows: the run-close check of the S3 log ---

const definiteHttp = (status) =>
  (status >= 200 && status <= 299) ||
  (status >= 400 && status <= 499 && ![408, 429, 499].includes(status));
const DEFINITE_GRPC = new Set([0, 3, 5, 6, 7, 9, 10, 11, 12, 16]);

test("every HTTP status but a 2xx or a 4xx other than 408, 429 and 499 is an unknown row", () => {
  for (let status = -3; status <= 1200; status += 1) {
    const line = `fs-ent-pipeline/o4/stages#select-empty ${status}`;
    assert.equal(isUnknownRow(line), !definiteHttp(status), line);
  }
  // A timeout (408) and a cancellation (499, gRPC CANCELLED) settle nothing.
  for (const status of [0, -1, 100, 103, 199, 301, 302, 304, 399, 408, 429, 499, 500, 503, 599]) {
    assert.equal(isUnknownRow(`p/a/b#s ${status}`), true, String(status));
  }
  for (const status of [200, 204, 400, 403, 404, 409, 412]) {
    assert.equal(isUnknownRow(`p/a/b#s ${status}`), false, String(status));
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

test("a step line whose outcome is not a plain integer is unknown (fail-closed)", () => {
  for (const line of [
    "p#s grpc undefined",
    "p#s undefined",
    "p#s null",
    "p#s NaN",
    "p#s grpc null",
    "p#s grpc UNAVAILABLE",
    "p#s 500 ",
    "p#s\t500",
    "p#s\t200",
    "p#s grpc  14",
    "p#s grpc  0",
    "p#s  200",
    "p#s 0200",
    "p#s +200",
    "p#s 200 extra",
    "p#s 200.0",
    "p#s grpc",
    "p#s grpc 0x0",
    "2026-10-20T00:00:00Z p#s 200 trailing",
    // More than one step outcome on one line: the earlier one must not hide.
    "p#s 503\rp#t 200",
    "p#s 503 p#t 200",
    "p#s 503\u0085p#t 200",
    "p#s 503\u2028p#t 200",
    "p#s 503p#t 200",
    "p#s 200\r\r",
    // A line break before a single step token (a CR-only rewrite of an earlier line).
    "garbage\rp#s 200",
    "\u0085p#s 200",
    // No sign but `-`, and no `-0`.
    "p#s grpc -0",
    "p#s -0",
  ]) {
    assert.equal(isStepLine(line), true, JSON.stringify(line));
    assert.equal(isUnknownRow(line), true, JSON.stringify(line));
  }
  // A log prefix before a plain step line is fine.
  assert.equal(isUnknownRow("2026-10-20T00:00:00Z p/a/b#s 200"), false);
  assert.equal(isUnknownRow("2026-10-20T00:00:00Z p/a/b#s 500"), true);
});

test("only step lines count: the summary, the ledger echo and other log lines never do", () => {
  const log = [
    "fs-ent-pipeline/o4/aliases#plain 200",
    "fs-ent-pipeline/o4/aliases#syntax 400",
    "fs-ent-pipeline/o4/documents#write-a 503",
    "{",
    '  "requests": 242,',
    '  "nondeterministic": [',
    '    "fs-ent-pipeline/o5/function-names#fn-rand",',
    "  ],",
    "fs-ent-pipeline/o4/documents#get-a 302",
    "HTTP 500 from the token endpoint",
    "fs-ent-pipeline/o4/stages#x 200 extra",
    "fs-ent-pipeline/o4/stages#y grpc 14",
    "",
  ].join("\n");
  assert.deepEqual(scanLog(log), {
    stepLines: 6,
    unknown: [
      { line: 3, text: "fs-ent-pipeline/o4/documents#write-a 503" },
      { line: 9, text: "fs-ent-pipeline/o4/documents#get-a 302" },
      { line: 11, text: "fs-ent-pipeline/o4/stages#x 200 extra" },
      { line: 12, text: "fs-ent-pipeline/o4/stages#y grpc 14" },
    ],
  });
  assert.deepEqual(unknownRows(log), scanLog(log).unknown);
  assert.deepEqual(scanLog("p#s 200\r\np#t 500\r\n"), {
    stepLines: 2,
    unknown: [{ line: 2, text: "p#t 500" }],
  });
  assert.equal(isUnknownRow("p#t 200\r"), false);
  assert.equal(isUnknownRow("p#t 500\r"), true);
  assert.deepEqual(scanLog("p#s 200\r\r\n"), {
    stepLines: 1,
    unknown: [{ line: 1, text: "p#s 200\r" }],
  });
  for (const line of ["{", "", '  "requests": 242,', "HTTP 500", '    "p#s",']) {
    assert.equal(isStepLine(line), false, JSON.stringify(line));
  }
});

const { execFile } = await import("node:child_process");
const { mkdir, symlink, writeFile: writeText } = await import("node:fs/promises");
const sourceDir = new URL("./fs-query-index/", import.meta.url).pathname;
const runNode = (args) =>
  new Promise((resolve) => {
    execFile(process.execPath, args, (error, stdout, stderr) =>
      resolve({ code: error ? error.code : 0, stdout, stderr }),
    );
  });

test("the CLI requires --expect and exits non-zero on an unknown row, on no step lines and on another count", async () => {
  const cli = join(sourceDir, "unknown-rows.mjs");
  await withDir(async (dir) => {
    const log = async (name, text) => {
      const path = join(dir, name);
      await writeText(path, text);
      return path;
    };
    const clean = await log("clean.log", "p#a 200\np#b 404\nq#c grpc 5\n{\n}\n");
    const unknown = await log("unknown.log", "p#a 200\np#b 503\n");
    const empty = await log("empty.log", "");
    const noSteps = await log("ledger.log", '{"ts":"x","outcome":"recorded"}\n');
    let out = await runNode([cli, clean, "--expect", "3"]);
    assert.equal(out.code, 0);
    assert.match(out.stdout, /step lines: 3\nunknown rows: 0\n$/);
    out = await runNode([cli, clean, "--expect", "4"]);
    assert.equal(out.code, 3);
    assert.match(out.stdout, /expected 4 step lines, saw 3/);
    out = await runNode([cli, unknown, "--expect", "2"]);
    assert.equal(out.code, 1);
    assert.match(out.stdout, /^2:p#b 503\n/);
    for (const path of [empty, noSteps]) {
      out = await runNode([cli, path, "--expect", "1"]);
      assert.equal(out.code, 3, path);
      assert.match(out.stdout, /step lines: 0/);
    }
    // --expect is required: without it nothing is judged.
    for (const args of [[clean], [], [clean, "--expect", "x"], [clean, "--expect", "0"]]) {
      out = await runNode([cli, ...args]);
      assert.equal(out.code, 2, JSON.stringify(args));
      assert.equal(out.stdout, "");
    }
  });
});

test("the CLIs run through a symlinked directory and a directory whose name holds a space", async () => {
  await withDir(async (dir) => {
    const spaced = join(dir, "a dir with space");
    await mkdir(spaced);
    // A symlink to the source directory, inside a directory whose name holds a space.
    const linked = join(spaced, "linked");
    await symlink(sourceDir, linked);
    const log = join(dir, "unknown.log");
    await writeText(log, "p#a 200\np#b 503\n");
    for (const base of [linked, sourceDir]) {
      const out = await runNode([join(base, "unknown-rows.mjs"), log, "--expect", "2"]);
      assert.equal(out.code, 1, base);
      assert.match(out.stdout, /^2:p#b 503\n/, base);
      // run.mjs runs its main block too: without a mode it prints its usage and exits 2.
      const usage = await runNode([join(base, "run.mjs")]);
      assert.equal(usage.code, 2, base);
      assert.match(usage.stderr, /^usage: run\.mjs /, base);
    }
  });
});
