// Replays of real recorded answers through the ownership library. The fixtures hold the action, the
// transport, the name (project removed), the status and whether a body was read of the mutating and
// reading requests of three production recordings: PUBSUB (REST and gRPC, one create that really
// timed out), the Cloud Scheduler shape run and calendar v5 (a delete of a paused job really
// answered 409), and FE v5 (storage objects, topics and a bucket). fixtures/ownership-replays/
// extract.py shows how each file is derived and carries the source digests.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  return op.transportError
    ? { transportError: true }
    : { status: op.status, bodyReadable: op.bodyReadable };
}

/** Drives the library the way a recorder would, and tallies what happened. */
function replay(ops, { reopenEvery = 0 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ownership-replay-"));
  const path = join(dir, "ledger.jsonl");
  let state = openOwnership({ path, runId: "replay" });
  const tally = {};
  const refusals = [];
  const count = (key) => {
    tally[key] = (tally[key] ?? 0) + 1;
  };
  const decisions = () =>
    JSON.stringify([...state.names.keys()].map((name) => [name, mayDelete(state, name)]));
  for (const [index, op] of ops.entries()) {
    const answer = answerOf(op);
    try {
      if (op.action === "create") {
        const ticket = beginCreate(state, { name: op.name, transport: op.transport });
        count(`create:${recordAnswer(state, ticket, answer).class}`);
      } else if (op.action === "delete") {
        const ticket = beginDelete(state, { name: op.name, transport: op.transport });
        count(`delete:${recordAnswer(state, ticket, answer).class}`);
      } else {
        count(`get:${recordRead(state, { name: op.name, transport: op.transport, answer })}`);
      }
    } catch (error) {
      assert.ok(error instanceof OwnershipError, String(error));
      refusals.push({ index, action: op.action, name: op.name, code: error.code });
    }
    if (reopenEvery > 0 && index % reopenEvery === reopenEvery - 1) {
      // A crash and resume between two requests changes no decision.
      const before = decisions();
      const report = closureReport(state);
      closeOwnership(state);
      state = openOwnership({ path, runId: "replay" });
      assert.equal(decisions(), before, `after op ${index}`);
      assert.deepEqual(closureReport(state), report, `after op ${index}`);
    }
  }
  const report = closureReport(state);
  const owned = (name) => isOwned(state, name);
  const rows = readLedger(path, "replay").rows;
  closeOwnership(state);
  rmSync(dir, { recursive: true, force: true });
  return { tally, refusals, report, owned, rows };
}

describe("replays of recorded production answers", () => {
  it("PUBSUB run 148026092d56: every delete was of a name the run created; one create really timed out", () => {
    const fx = fixture("pubsub-r1.json");
    assert.equal(fx.ops.length, 223);
    const result = replay(fx.ops);
    assert.deepEqual(result.tally, {
      "get:absent": 13,
      "get:present": 40,
      "get:unknown": 5,
      "create:ok": 103,
      "create:conflict": 4,
      "create:notFound": 6,
      "create:refused": 42,
      "create:unknown": 1,
      "delete:ok": 5,
      "delete:notFound": 4,
    });
    assert.deepEqual(result.refusals, [], "the real deletes were all of names this run created");
    // The one create that timed out (a transport error after 30 s) stays unsettled: no GET of that
    // name followed, so the library neither owns it nor lets it be deleted.
    assert.deepEqual(result.report.unsettled, ["topics/fe148026092d56-lc-r-t"]);
    assert.equal(result.owned("topics/fe148026092d56-lc-r-t"), false);
    assert.equal(result.report.unknownDeletes, 0);
    assert.equal(result.report.closureReady, false);
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
    // Everything the run still owns is a name its own create answered 200 for.
    for (const name of result.report.owned) {
      assert.ok(
        fx.ops.some((op) => op.action === "create" && op.name === name && op.status === 200),
        name,
      );
    }
  });

  it("PUBSUB: a resume between any two requests changes no decision", () => {
    const fx = fixture("pubsub-r1.json");
    const plain = replay(fx.ops);
    const resumed = replay(fx.ops, { reopenEvery: 7 });
    assert.deepEqual(resumed.tally, plain.tally);
    // The two replays ran at different real times, so compare the reports without the times.
    const untimed = (report) => ({
      ...report,
      details: report.details.map(({ name, action, reason }) => ({ name, action, reason })),
    });
    assert.deepEqual(untimed(resumed.report), untimed(plain.report));
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

  it("every fixture names its sources by digest and holds no project id or number", () => {
    for (const name of ["pubsub-r1.json", "scheduler.json", "fe-v5.json"]) {
      const text = readFileSync(new URL(name, FIXTURES), "utf8");
      const fx = JSON.parse(text);
      assert.ok(fx.sources.length >= 1);
      for (const source of fx.sources) {
        assert.match(source.sha256, /^[0-9a-f]{64}$/u);
        assert.match(source.path, /\.jsonl$/u);
      }
      assert.doesNotMatch(text, /fireemu-oracle/u, name);
      assert.doesNotMatch(text, /\b\d{12}\b/u, name);
      for (const op of fx.ops) {
        assert.ok(["create", "delete", "get"].includes(op.action));
        assert.ok(["rest", "grpc"].includes(op.transport));
        assert.equal(typeof op.name, "string");
      }
    }
  });
});
