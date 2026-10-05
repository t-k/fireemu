// Replays of real recorded answers through the ownership library. The fixtures hold the action, the
// transport, the name (project removed), the status and whether a body was read of the mutating and
// reading requests of three production recordings: PUBSUB (REST and gRPC, one create that really
// timed out), the Cloud Scheduler shape run and calendar v5 (a delete of a paused job really
// answered 409), and FE v5 (storage objects, topics and a bucket). fixtures/ownership-replays/
// extract.py shows how each file is derived and carries the source digests.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

import {
  beginCreate,
  beginDelete,
  closeOwnership,
  closureReport,
  isOwned,
  mayDelete,
  openOwnership,
  OwnershipError,
  readLedger,
  recordAnswer,
  recordRead,
} from "./ownership.mjs";

const FIXTURES = new URL("./fixtures/ownership-replays/", import.meta.url);

function fixture(name) {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
}

function answerOf(op) {
  if (op.transportError) return { transportError: true };
  const answer = { status: op.status, bodyReadable: op.bodyReadable };
  // A present GET carries the name its recorded body showed.
  return op.bodyName === undefined ? answer : { ...answer, bodyName: op.bodyName };
}

/** Sends one recorded request through the library; returns its tally key. */
function applyOp(state, op, answer = answerOf(op)) {
  if (op.action === "create") {
    const ticket = beginCreate(state, { name: op.name, transport: op.transport });
    return `create:${recordAnswer(state, ticket, answer).class}`;
  }
  if (op.action === "delete") {
    const ticket = beginDelete(state, { name: op.name, transport: op.transport });
    return `delete:${recordAnswer(state, ticket, answer).class}`;
  }
  return `get:${recordRead(state, { name: op.name, transport: op.transport, answer })}`;
}

/**
 * Drives the library the way a recorder would, and tallies what happened. The clock follows the
 * recorded time of each request when the fixture has it (PUBSUB), and moves one second per request
 * otherwise. With `keep`, the ledger stays open and `close` ends it.
 */
function replay(ops, { reopenEvery = 0, keep = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ownership-replay-"));
  const path = join(dir, "ledger.jsonl");
  const clock = { now: ops[0]?.at ? Date.parse(ops[0].at) : 1_788_000_000_000 };
  const now = () => clock.now;
  // The rows are really written; the flush to disk is left out, which no replay decision depends on.
  const io = { writeSync, fsyncSync: () => {} };
  let state = openOwnership({ path, runId: "replay", now, io });
  const tally = {};
  const refusals = [];
  const count = (key) => {
    tally[key] = (tally[key] ?? 0) + 1;
  };
  const decisions = () =>
    JSON.stringify([...state.names.keys()].map((name) => [name, mayDelete(state, name)]));
  for (const [index, op] of ops.entries()) {
    clock.now = op.at ? Date.parse(op.at) : clock.now + 1000;
    const answer = answerOf(op);
    try {
      count(applyOp(state, op, answer));
    } catch (error) {
      assert.ok(error instanceof OwnershipError, String(error));
      refusals.push({ index, action: op.action, name: op.name, code: error.code });
    }
    if (reopenEvery > 0 && index % reopenEvery === reopenEvery - 1) {
      // A crash and resume between two requests changes no decision.
      const before = decisions();
      const report = closureReport(state);
      closeOwnership(state);
      state = openOwnership({ path, runId: "replay", now, io });
      assert.equal(decisions(), before, `after op ${index}`);
      assert.deepEqual(closureReport(state), report, `after op ${index}`);
    }
  }
  const report = closureReport(state);
  const owned = (name) => isOwned(state, name);
  const rows = readLedger(path, "replay").rows;
  const close = () => {
    closeOwnership(state);
    rmSync(dir, { recursive: true, force: true });
  };
  if (!keep) close();
  return { tally, refusals, report, owned, rows, state, clock, close };
}

describe("replays of recorded production answers", () => {
  it("PUBSUB run 148026092d56 (complete capture): the cleanup delete of the create that timed out is the one refusal", () => {
    const fx = fixture("pubsub-r1.json");
    assert.equal(fx.ops.length, 565);
    assert.equal(fx.sources[0].lines, 1088, "the whole capture, not its first 472 lines");
    const result = replay(fx.ops);
    assert.deepEqual(result.tally, {
      "get:absent": 157,
      "get:present": 58,
      "get:unknown": 12,
      "create:ok": 137,
      "create:conflict": 4,
      "create:notFound": 6,
      "create:refused": 48,
      "create:unknown": 1,
      "delete:ok": 137,
      "delete:notFound": 4,
    });
    // The create that timed out after 30 s (21:29:49Z) was still there at the cleanup, 40 minutes
    // later: the run's own DELETE of it is refused, because no own GET of that name showed it.
    const timedOut = "topics/fe148026092d56-lc-r-t";
    assert.deepEqual(
      result.refusals.map(({ action, name, code }) => [action, name, code]),
      [["delete", timedOut, "unsettled"]],
    );
    assert.equal(
      fx.ops[result.refusals[0].index].status,
      200,
      "production answered the delete 200",
    );
    // Every other delete was of a name this run created; the timed-out create stays unowned, and the
    // GETs that found nothing (the name probes) did not settle it, even though they came much
    // later than the settle delay.
    assert.deepEqual(result.report.unsettled, [timedOut]);
    assert.equal(result.owned(timedOut), false);
    assert.equal(result.report.unknownDeletes, 0);
    assert.equal(result.report.closureReady, false);
    assert.deepEqual(result.report.absentUnconfirmed, [timedOut]);
    assert.deepEqual(result.report.reasons, [
      `unsettled-create:${timedOut}`,
      `unknown-create-absent-unconfirmed:${timedOut}`,
    ]);
    assert.equal(result.report.a2Required, true);
    const [entry] = result.report.unknownAnswers;
    assert.deepEqual(
      [entry.name, entry.action, entry.reason, entry.settled, entry.absentReads.length > 0],
      [timedOut, "create", "transport-error", false, true],
    );
    // A name whose create answered 409, 404 or 400 was never ours.
    const notOurs = new Set(
      fx.ops.filter((op) => op.action === "create" && op.status !== 200).map((op) => op.name),
    );
    for (const name of notOurs) {
      const succeeded = fx.ops.some(
        (op) => op.action === "create" && op.name === name && op.status === 200,
      );
      if (!succeeded) assert.equal(result.owned(name), false, name);
    }
    // Nothing is left owned: every name whose own create answered 200 was deleted.
    assert.deepEqual(result.report.owned, []);
  });

  it("PUBSUB: the timed-out create is deletable only after an own GET shows it, and then the run can close", () => {
    const fx = fixture("pubsub-r1.json");
    const name = "topics/fe148026092d56-lc-r-t";
    const created = fx.ops.findIndex((op) => op.action === "create" && op.name === name);
    const refused = fx.ops.findLastIndex((op) => op.action === "delete" && op.name === name);
    assert.ok(created >= 0 && refused > created);
    const minutes = (Date.parse(fx.ops[refused].at) - Date.parse(fx.ops[created].at)) / 60_000;
    assert.ok(
      minutes > 39 && minutes < 41,
      `${minutes} minutes between the create and its cleanup`,
    );
    const run = replay(fx.ops.slice(0, refused), { keep: true });
    try {
      const { state, clock } = run;
      clock.now = Date.parse(fx.ops[refused].at);
      const tryDelete = () => {
        try {
          beginDelete(state, { name, transport: "rest" });
        } catch (error) {
          assert.ok(error instanceof OwnershipError, String(error));
          return error.code;
        }
        return "allowed";
      };
      assert.equal(tryDelete(), "unsettled");
      // A GET that finds nothing, 40 minutes late, still settles nothing.
      assert.equal(
        recordRead(state, { name, transport: "rest", answer: { status: 404, bodyReadable: true } }),
        "absent",
      );
      assert.equal(tryDelete(), "unsettled");
      // The recorded list of 22:06Z showed the name; a direct GET of it is the own read. Without the
      // body naming it, it counts for nothing.
      const get = { status: 200, bodyReadable: true };
      assert.equal(recordRead(state, { name, transport: "rest", answer: get }), "unknown");
      assert.equal(tryDelete(), "unsettled");
      assert.equal(
        recordRead(state, { name, transport: "rest", answer: { ...get, bodyName: name } }),
        "present",
      );
      assert.equal(applyOp(state, fx.ops[refused]), "delete:ok");
      for (const op of fx.ops.slice(refused + 1)) {
        clock.now = Date.parse(op.at);
        applyOp(state, op); // the rest of the cleanup refuses nothing: a refusal would throw
      }
      const report = closureReport(state);
      assert.equal(report.closureReady, true);
      const [entry] = report.unknownAnswers;
      assert.deepEqual(
        [entry.name, entry.state, entry.settledBy],
        [name, "settled-present", "present"],
      );
      assert.equal(
        report.a2Required,
        true,
        "the unknown create is still named for the A2 read-back",
      );
    } finally {
      run.close();
    }
  });

  it("PUBSUB: a resume between any two requests changes no decision", () => {
    const fx = fixture("pubsub-r1.json");
    const plain = replay(fx.ops);
    const resumed = replay(fx.ops, { reopenEvery: 7 });
    assert.deepEqual(resumed.tally, plain.tally);
    assert.deepEqual(resumed.refusals, plain.refusals);
    // The ledger rows carry their times, which come from the recorded requests, so the reports match.
    assert.deepEqual(resumed.report, plain.report);
  });

  it("Cloud Scheduler: the delete of a paused job answered 409, so the job and the calendar topic stay owned", () => {
    const fx = fixture("scheduler.json");
    const result = replay(fx.ops);
    assert.deepEqual(result.tally, {
      "get:absent": 5,
      "get:present": 1,
      "create:ok": 10,
      "create:refused": 2,
      "delete:ok": 8,
      "delete:conflict": 1,
    });
    assert.deepEqual(result.refusals, []);
    // The real run left exactly these behind (the paused job, and the calendar topic it kept).
    assert.deepEqual(result.report.owned, ["jobs/shape", "topics/calendar"]);
    assert.equal(result.report.closureReady, false);
    assert.deepEqual(result.report.reasons, [
      "owned-not-deleted:jobs/shape",
      "owned-not-deleted:topics/calendar",
    ]);
    // The two job creates answered 400 never became ours.
    assert.equal(result.owned("jobs/c07"), false);
    assert.equal(result.owned("jobs/c08"), false);
  });

  it("FE v5: every cleanup was permitted, and the two deletes of never-created names are refused as probes", () => {
    const fx = fixture("fe-v5.json");
    const result = replay(fx.ops);
    assert.deepEqual(result.tally, { "create:ok": 25, "delete:ok": 23 });
    assert.equal(result.refusals.length, 2);
    for (const refusal of result.refusals) {
      assert.equal(refusal.code, "not-owned");
      const op = fx.ops[refusal.index];
      // These are the recorded storage-delete-missing probes: a delete of an object nobody
      // created, answered 404 by production. The library cannot tell a probe from a mistake, so a
      // recorder issues such a probe outside the ledger, with a name that cannot exist.
      assert.equal(op.action, "delete");
      assert.equal(op.status, 404);
    }
    assert.equal(result.report.closureReady, true);
    assert.deepEqual(result.report.reasons, []);
  });

  it("every fixture names its sources by digest and size and holds no project id or number", () => {
    for (const name of ["pubsub-r1.json", "scheduler.json", "fe-v5.json"]) {
      const text = readFileSync(new URL(name, FIXTURES), "utf8");
      const fx = JSON.parse(text);
      assert.ok(fx.sources.length >= 1);
      for (const source of fx.sources) {
        assert.match(source.sha256, /^[0-9a-f]{64}$/u);
        assert.match(source.path, /\.jsonl$/u);
        assert.ok(Number.isInteger(source.bytes) && source.bytes > 0, name);
        assert.ok(Number.isInteger(source.lines) && source.lines > 0, name);
      }
      assert.doesNotMatch(text, /fireemu-oracle/u, name);
      assert.doesNotMatch(text, /\b\d{12}\b/u, name);
      for (const op of fx.ops) {
        assert.ok(["create", "delete", "get"].includes(op.action));
        assert.ok(["rest", "grpc"].includes(op.transport));
        assert.equal(typeof op.name, "string");
        if (op.bodyName !== undefined) assert.equal(op.action, "get");
      }
    }
  });

  it("extract.py's decisions pass their own tests (synthetic captures, no private record needed)", () => {
    const run = spawnSync("python3", ["-m", "unittest", "test_extract"], {
      cwd: fileURLToPath(FIXTURES),
      encoding: "utf8",
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });
    assert.equal(run.status, 0, run.stderr);
  });

  const runs = privateRunsDir();
  const skip = runs === null ? "docs.local/runs is not here (a clean checkout or CI)" : false;

  it(
    "every fixture's source digest, size and line count match the private run record",
    { skip },
    () => {
      for (const name of ["pubsub-r1.json", "scheduler.json", "fe-v5.json"]) {
        const fx = fixture(name);
        for (const source of fx.sources) {
          const data = readFileSync(join(runs, source.path));
          const where = `${name}: ${source.path}`;
          assert.equal(createHash("sha256").update(data).digest("hex"), source.sha256, where);
          assert.equal(data.length, source.bytes, where);
          assert.equal(data.toString("utf8").split("\n").length - 1, source.lines, where);
        }
      }
    },
  );

  it(
    "extract.py regenerates every fixture byte for byte from the private run records",
    { skip },
    () => {
      const out = mkdtempSync(join(tmpdir(), "ownership-extract-"));
      try {
        const run = spawnSync(
          "python3",
          [fileURLToPath(new URL("extract.py", FIXTURES)), runs, out],
          {
            encoding: "utf8",
          },
        );
        assert.equal(run.status, 0, run.stderr);
        for (const name of ["pubsub-r1.json", "scheduler.json", "fe-v5.json"]) {
          assert.ok(
            readFileSync(join(out, name)).equals(readFileSync(new URL(name, FIXTURES))),
            `${name} differs from what extract.py derives`,
          );
        }
      } finally {
        rmSync(out, { recursive: true, force: true });
      }
    },
  );
});

/** The private run records, found from the checkout upwards or by OWNERSHIP_RUNS_DIR; null when absent. */
function privateRunsDir() {
  if (process.env.OWNERSHIP_RUNS_DIR) return resolve(process.env.OWNERSHIP_RUNS_DIR);
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(dir, "docs.local", "runs");
    if (existsSync(candidate)) return candidate;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}
