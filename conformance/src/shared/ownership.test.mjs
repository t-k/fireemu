import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import * as fs from "node:fs";

import {
  MAX_SETTLE_DELAY_MS,
  SETTLE_ABSENT_AFTER_MS as SETTLE_CONST,
  acceptUnconfirmed,
  ANSWER_CLASSES,
  beginCreate,
  beginDelete,
  classifyAnswer,
  classifyRead,
  closeOwnership,
  closureReport,
  isOwned,
  mayDelete,
  openOwnership,
  OwnershipError,
  readLedger,
  recordAnswer,
  recordRead,
  unsettledNames,
} from "./ownership.mjs";

const OK = { status: 200, bodyReadable: true };
const NO_CONTENT = { status: 204, bodyReadable: true };
const CONFLICT = { status: 409, bodyReadable: true };
const NOT_FOUND = { status: 404, bodyReadable: true };
const TIMEOUT = { transportError: true };

let dir;
let state;
let events;
let clock;
const START = 1_788_000_000_000;
const SETTLE = 10 * 60 * 1000;
const advance = (ms) => {
  clock += ms;
};

/** An io pair that records the order of writes and fsyncs, so durability can be asserted. */
function spyIo() {
  return {
    writeSync(fd, buffer, offset, length) {
      events.push("write");
      return fs.writeSync(fd, buffer, offset, length);
    },
    fsyncSync(fd) {
      events.push("fsync");
      return fs.fsyncSync(fd);
    },
  };
}

function open(name = "ledger.jsonl", runId = "run1") {
  return openOwnership({ path: join(dir, name), runId, io: spyIo(), now: () => clock });
}

function create(name, answer, transport = "rest") {
  const ticket = beginCreate(state, { name, transport });
  return recordAnswer(state, ticket, answer);
}

function remove(name, answer, transport = "rest") {
  const ticket = beginDelete(state, { name, transport });
  return recordAnswer(state, ticket, answer);
}

/** A direct GET of `name`. A present answer carries the name its body shows, as a recorder reads it. */
function read(name, answer, transport = "rest") {
  const shown = answer.status >= 200 && answer.status < 300 && !("bodyName" in answer);
  return recordRead(state, {
    name,
    transport,
    answer: shown ? { ...answer, bodyName: name } : answer,
  });
}

function refusal(fn) {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof OwnershipError, String(error));
    return error.code;
  }
  assert.fail("expected an OwnershipError");
}

beforeEach(() => {
  clock = START;
  dir = mkdtempSync(join(tmpdir(), "ownership-"));
  events = [];
  state = open();
  events.length = 0;
});

afterEach(() => {
  closeOwnership(state);
  rmSync(dir, { recursive: true, force: true });
});

describe("answer classes", () => {
  const table = [
    [{ status: 200, bodyReadable: true }, "ok", undefined],
    [{ status: 201, bodyReadable: true }, "ok", undefined],
    [{ status: 204, bodyReadable: true }, "ok", undefined],
    [{ status: 299, bodyReadable: true }, "ok", undefined],
    [{ status: 409, bodyReadable: true }, "conflict", undefined],
    [{ status: 404, bodyReadable: true }, "notFound", undefined],
    [{ status: 400, bodyReadable: true }, "refused", undefined],
    [{ status: 403, bodyReadable: true }, "refused", undefined],
    [{ status: 429, bodyReadable: true }, "refused", undefined],
    [{ status: 499, bodyReadable: true }, "unknown", "cancelled"],
    [{ status: 408, bodyReadable: true }, "unknown", "request-timeout"],
    [{ status: 498, bodyReadable: true }, "refused", undefined],
    [{ status: 407, bodyReadable: true }, "refused", undefined],
    [{ status: 499, bodyReadable: false }, "unknown", "unreadable-body"],
    [{ status: 199, bodyReadable: true }, "unknown", "status-below-200"],
    [{ status: 100, bodyReadable: true }, "unknown", "status-below-200"],
    [{ status: 0, bodyReadable: true }, "unknown", "status-below-200"],
    [{ status: 300, bodyReadable: true }, "unknown", "redirect"],
    [{ status: 302, bodyReadable: true }, "unknown", "redirect"],
    [{ status: 399, bodyReadable: true }, "unknown", "redirect"],
    [{ status: 500, bodyReadable: true }, "unknown", "server-error"],
    [{ status: 503, bodyReadable: true }, "unknown", "server-error"],
    [{ status: 599, bodyReadable: true }, "unknown", "server-error"],
    [{ status: 600, bodyReadable: true }, "unknown", "invalid-status"],
    [{ status: 200, bodyReadable: false }, "unknown", "unreadable-body"],
    [{ status: 200 }, "unknown", "unreadable-body"],
    [{ status: 404, bodyReadable: false }, "unknown", "unreadable-body"],
    [{ status: 409 }, "unknown", "unreadable-body"],
    [{ transportError: true }, "unknown", "transport-error"],
    [
      { transportError: "ETIMEDOUT", status: 200, bodyReadable: true },
      "unknown",
      "transport-error",
    ],
    [{ bodyReadable: true }, "unknown", "invalid-status"],
    [{ status: "200", bodyReadable: true }, "unknown", "invalid-status"],
    [{ status: 200.5, bodyReadable: true }, "unknown", "invalid-status"],
    [{ status: -1, bodyReadable: true }, "unknown", "invalid-status"],
    [{ status: 1000, bodyReadable: true }, "unknown", "invalid-status"],
    [{ status: 200, bodyReadable: true, operationPending: true }, "unknown", "operation-pending"],
  ];
  for (const [answer, klass, reason] of table) {
    it(`${JSON.stringify(answer)} is ${klass}${reason ? ` (${reason})` : ""}`, () => {
      const result = classifyAnswer(answer);
      assert.equal(result.class, klass);
      assert.equal(result.reason, reason);
    });
  }

  it("refuses an answer that is not an object", () => {
    for (const bad of [null, undefined, 200, "ok"]) {
      assert.throws(
        () => classifyAnswer(bad),
        (error) => error.code === "bad-answer",
      );
    }
  });

  it("keeps the status of an unknown answer when there is one", () => {
    assert.equal(classifyAnswer({ status: 503, bodyReadable: true }).status, 503);
    assert.equal(classifyAnswer({ transportError: true }).status, null);
  });

  it("reads a GET as present, absent or unknown", () => {
    assert.equal(classifyRead(OK).observed, "present");
    assert.equal(classifyRead(NOT_FOUND).observed, "absent");
    for (const answer of [
      CONFLICT,
      { status: 403, bodyReadable: true },
      TIMEOUT,
      { status: 200, bodyReadable: false },
      { status: 503, bodyReadable: true },
    ]) {
      assert.equal(classifyRead(answer).observed, "unknown", JSON.stringify(answer));
    }
  });
});

describe("the issued-names ledger", () => {
  it("writes an intent row and fsyncs before beginCreate returns, and the answer row after", () => {
    beginCreate(state, { name: "topics/a", transport: "rest" });
    assert.deepEqual(
      events,
      ["write", "fsync"],
      "the intent is durable before the request may be sent",
    );
    const afterIntent = readFileSync(join(dir, "ledger.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    assert.equal(afterIntent.length, 2, "the open row, then the intent");
    assert.deepEqual(
      {
        phase: afterIntent[1].phase,
        action: afterIntent[1].action,
        name: afterIntent[1].name,
        transport: afterIntent[1].transport,
      },
      { phase: "intent", action: "create", name: "topics/a", transport: "rest" },
    );
    events.length = 0;
    const ticket = state.names.get("topics/a").open;
    recordAnswer(state, { ...ticket }, OK);
    assert.deepEqual(events, ["write", "fsync"]);
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows;
    assert.deepEqual(
      rows.map((r) => r.phase),
      ["open", "intent", "answer"],
    );
    assert.equal(rows[2].class, "ok");
    assert.equal(rows[2].status, 200);
    assert.equal(rows[2].transport, "rest");
    assert.equal(rows[2].name, "topics/a");
  });

  it("fsyncs a delete intent and its answer, a read and a refused delete too", () => {
    create("topics/a", OK);
    events.length = 0;
    const ticket = beginDelete(state, { name: "topics/a", transport: "grpc" });
    assert.deepEqual(events, ["write", "fsync"]);
    recordAnswer(state, ticket, NO_CONTENT);
    assert.deepEqual(events, ["write", "fsync", "write", "fsync"]);
    events.length = 0;
    read("topics/a", NOT_FOUND);
    assert.deepEqual(events, ["write", "fsync"]);
    events.length = 0;
    refusal(() => beginDelete(state, { name: "topics/foreign", transport: "rest" }));
    assert.deepEqual(events, ["write", "fsync"], "a refusal is an audit row");
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows;
    assert.deepEqual(
      rows.map((r) => r.phase),
      ["open", "intent", "answer", "intent", "answer", "read", "guard"],
    );
    assert.equal(rows.at(-1).allowed, false);
    assert.equal(rows.at(-1).reason, "not-owned");
  });

  it("numbers rows from 1 and stamps the run and the time", () => {
    create("topics/a", OK);
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows;
    assert.deepEqual(
      rows.map((r) => r.seq),
      [1, 2, 3],
    );
    assert.ok(rows.every((r) => r.runId === "run1" && r.v === 1));
    assert.ok(rows.every((r) => r.at === new Date(START).toISOString()));
  });

  it("records the transport and the answer class of every answer", () => {
    create("topics/a", OK, "grpc");
    create("topics/b", TIMEOUT, "rest");
    create("topics/c", CONFLICT, "cli");
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows.filter(
      (r) => r.phase === "answer",
    );
    assert.deepEqual(
      rows.map((r) => [r.transport, r.class]),
      [
        ["grpc", "ok"],
        ["rest", "unknown"],
        ["cli", "conflict"],
      ],
    );
    assert.equal(rows[1].reason, "transport-error");
  });

  it("refuses names and transports it cannot record", () => {
    for (const name of ["", "a\u0000b", "a\nb", "x".repeat(1025), 5, null, undefined, "a\u007fb"]) {
      assert.equal(
        refusal(() => beginCreate(state, { name, transport: "rest" })),
        "bad-name",
        JSON.stringify(name),
      );
    }
    for (const transport of ["", "REST", "a b", "x".repeat(40), 5, undefined, "-rest"]) {
      assert.equal(
        refusal(() => beginCreate(state, { name: "a", transport })),
        "bad-transport",
        JSON.stringify(transport),
      );
    }
    assert.deepEqual(
      readLedger(join(dir, "ledger.jsonl"), "run1").rows.map((r) => r.phase),
      ["open"],
      "nothing was written but the open row",
    );
    assert.doesNotThrow(() =>
      beginCreate(state, { name: "x".repeat(1024), transport: "a".repeat(32) }),
    );
  });

  it("refuses a second request on a name while one is in flight", () => {
    beginCreate(state, { name: "a", transport: "rest" });
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "in-flight",
    );
    assert.equal(
      refusal(() => beginDelete(state, { name: "a", transport: "rest" })),
      "in-flight",
    );
    assert.equal(
      refusal(() => read("a", OK)),
      "in-flight",
    );
  });

  it("refuses an answer for a ticket that is not open", () => {
    const ticket = beginCreate(state, { name: "a", transport: "rest" });
    recordAnswer(state, ticket, OK);
    assert.equal(
      refusal(() => recordAnswer(state, ticket, OK)),
      "stale-ticket",
    );
    assert.equal(
      refusal(() =>
        recordAnswer(state, { ticket: 1, action: "create", name: "never", transport: "rest" }, OK),
      ),
      "stale-ticket",
    );
    const other = beginCreate(state, { name: "b", transport: "rest" });
    assert.equal(
      refusal(() => recordAnswer(state, { ...other, ticket: other.ticket + 7 }, OK)),
      "stale-ticket",
    );
  });

  it("refuses writes after close", () => {
    closeOwnership(state);
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "closed",
    );
    closeOwnership(state);
    state = open("second.jsonl");
  });

  it("says the state is closed before it judges anything else about a call", () => {
    create("u", TIMEOUT);
    create("o", OK);
    beginCreate(state, { name: "f", transport: "rest" });
    closeOwnership(state);
    const calls = [
      () => beginCreate(state, { name: "", transport: "rest" }),
      () => beginCreate(state, { name: "u", transport: "rest" }),
      () => beginCreate(state, { name: "f", transport: "rest" }),
      () => beginCreate(state, { name: "new", transport: "bad transport" }),
      () => beginDelete(state, { name: "", transport: "rest" }),
      () => beginDelete(state, { name: "never", transport: "rest" }),
      () => beginDelete(state, { name: "o", transport: "rest" }),
      () => recordRead(state, { name: "", transport: "rest", answer: OK }),
      () => recordRead(state, { name: "f", transport: "rest", answer: OK }),
      () => recordAnswer(state, { ticket: 3, action: "create", name: "f", transport: "rest" }, OK),
      () =>
        recordAnswer(state, { ticket: 99, action: "create", name: "zz", transport: "rest" }, OK),
    ];
    for (const call of calls) assert.equal(refusal(call), "closed");
    state = open("second.jsonl");
  });

  it("closes once: a second close touches neither a reused descriptor nor another writer's lock", () => {
    closeOwnership(state);
    const path = join(dir, "twice.jsonl");
    const first = openOwnership({ path, runId: "run1" });
    closeOwnership(first);
    // The descriptor number is free now and a new file is likely to get it.
    const other = fs.openSync(join(dir, "other-file"), "w");
    // Another writer holds the lock now (a process that is alive).
    writeFileSync(`${path}.lock`, `${process.ppid}\n`);
    closeOwnership(first);
    assert.doesNotThrow(() => fs.fstatSync(other), "the other file's descriptor is still open");
    assert.equal(readFileSync(`${path}.lock`, "utf8"), `${process.ppid}\n`, "the other lock stays");
    fs.closeSync(other);
    rmSync(`${path}.lock`);
    state = open("second.jsonl");
  });

  it("a failed or short write is an error, never a silent success", () => {
    closeOwnership(state);
    let broken = false;
    state = openOwnership({
      path: join(dir, "broken.jsonl"),
      runId: "run1",
      io: {
        writeSync: (fd, buffer, offset, length) =>
          broken ? 0 : fs.writeSync(fd, buffer, offset, length),
        fsyncSync: () => {},
      },
    });
    broken = true;
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "ledger-write",
    );
    assert.equal(
      refusal(() => beginCreate(state, { name: "b", transport: "rest" })),
      "ledger-failed",
    );
    assert.throws(
      () =>
        openOwnership({
          path: join(dir, "broken2.jsonl"),
          runId: "run1",
          io: { writeSync: () => 0, fsyncSync: () => {} },
        }),
      (error) => error.code === "ledger-write",
      "a new ledger whose first row cannot be written",
    );
  });

  it("keeps writing after a short write that made progress", () => {
    closeOwnership(state);
    state = openOwnership({
      path: join(dir, "chunks.jsonl"),
      runId: "run1",
      io: {
        writeSync: (fd, buffer, offset, length) =>
          fs.writeSync(fd, buffer, offset, Math.min(length, 7)),
        fsyncSync: (fd) => fs.fsyncSync(fd),
      },
    });
    create("topics/a", OK);
    assert.equal(readLedger(join(dir, "chunks.jsonl"), "run1").rows.length, 3);
  });
});

describe("the delete guard", () => {
  it("refuses a name this run never created", () => {
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/foreign", transport: "rest" })),
      "not-owned",
    );
    assert.deepEqual(mayDelete(state, "topics/foreign"), { allowed: false, reason: "not-owned" });
  });

  it("allows a name whose own create answered 2xx, and again after its own delete (a probe of a deleted name)", () => {
    create("topics/a", OK);
    assert.deepEqual(mayDelete(state, "topics/a"), { allowed: true, reason: "create" });
    assert.equal(isOwned(state, "topics/a"), true);
    assert.equal(remove("topics/a", NO_CONTENT).class, "ok");
    assert.equal(isOwned(state, "topics/a"), false, "nothing of ours is left");
    assert.deepEqual(mayDelete(state, "topics/a"), { allowed: true, reason: "create" });
    assert.equal(remove("topics/a", NOT_FOUND).class, "notFound");
    assert.equal(closureReport(state).closureReady, false, "its own delete is not read back yet");
    read("topics/a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
  });

  it("does not own a name whose create answered 409, 404 or another 4xx", () => {
    for (const [name, answer] of [
      ["c409", CONFLICT],
      ["c404", NOT_FOUND],
      ["c400", { status: 400, bodyReadable: true }],
      ["c403", { status: 403, bodyReadable: true }],
    ]) {
      create(name, answer);
      assert.equal(isOwned(state, name), false, name);
      assert.equal(
        refusal(() => beginDelete(state, { name, transport: "rest" })),
        "not-owned",
        name,
      );
    }
  });

  it("a 409 on a retry does not take ownership away from an earlier 2xx", () => {
    create("topics/a", OK);
    create("topics/a", CONFLICT);
    assert.equal(isOwned(state, "topics/a"), true);
  });

  it("does not own a name whose create answered unknown, until a GET shows it", () => {
    for (const [name, answer] of [
      ["t", TIMEOUT],
      ["s500", { status: 503, bodyReadable: true }],
      ["r302", { status: 302, bodyReadable: true }],
      ["u", { status: 200, bodyReadable: false }],
      ["p", { ...OK, operationPending: true }],
    ]) {
      assert.equal(create(name, answer).class, "unknown", name);
      assert.equal(isOwned(state, name), false, name);
      assert.equal(
        refusal(() => beginDelete(state, { name, transport: "rest" })),
        "unsettled",
        name,
      );
    }
    assert.deepEqual(unsettledNames(state), ["p", "r302", "s500", "t", "u"]);
  });

  it("owns an unknown create once a later direct GET shows the name", () => {
    create("topics/a", TIMEOUT);
    assert.equal(read("topics/a", OK), "present");
    assert.equal(isOwned(state, "topics/a"), true);
    assert.deepEqual(mayDelete(state, "topics/a"), { allowed: true, reason: "settled-read" });
    assert.equal(remove("topics/a", NO_CONTENT).class, "ok");
    read("topics/a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
  });

  it("does not own an unknown create when a GET, after the settle delay, finds nothing, and does not settle it either", () => {
    create("topics/a", TIMEOUT);
    advance(SETTLE);
    assert.equal(read("topics/a", NOT_FOUND), "absent");
    assert.equal(isOwned(state, "topics/a"), false);
    assert.deepEqual(unsettledNames(state), ["topics/a"], "absence alone never settles a create");
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "unsettled",
    );
    const report = closureReport(state);
    assert.equal(report.closureReady, false, "a timed-out create may still appear");
    assert.deepEqual(report.reasons, [
      "unsettled-create:topics/a",
      "unknown-create-absent-unconfirmed:topics/a",
    ]);
  });

  it("leaves an unknown create unsettled when the GET is itself unknown", () => {
    create("topics/a", TIMEOUT);
    for (const answer of [
      TIMEOUT,
      { status: 503, bodyReadable: true },
      { status: 403, bodyReadable: true },
      { status: 200, bodyReadable: false },
      CONFLICT,
    ]) {
      assert.equal(read("topics/a", answer), "unknown");
      assert.deepEqual(unsettledNames(state), ["topics/a"]);
      assert.equal(
        refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
        "unsettled",
      );
    }
  });

  it("refuses a GET whose body names another name as a settlement", () => {
    create("topics/a", TIMEOUT);
    const answer = { ...OK, bodyName: "topics/other" };
    assert.equal(recordRead(state, { name: "topics/a", transport: "rest", answer }), "unknown");
    assert.equal(isOwned(state, "topics/a"), false);
    assert.equal(
      recordRead(state, {
        name: "topics/a",
        transport: "rest",
        answer: { ...OK, bodyName: "topics/a" },
      }),
      "present",
    );
    assert.equal(isOwned(state, "topics/a"), true);
  });

  it("never makes a name owned by a GET alone", () => {
    assert.equal(read("topics/foreign", OK), "present");
    assert.equal(isOwned(state, "topics/foreign"), false);
    create("topics/b", CONFLICT);
    assert.equal(read("topics/b", OK), "present");
    assert.equal(
      isOwned(state, "topics/b"),
      false,
      "a 409 means the name was not ours, and a GET cannot change that",
    );
  });

  it("refuses a new create or delete on a name with an unsettled answer", () => {
    create("topics/a", TIMEOUT);
    assert.equal(
      refusal(() => beginCreate(state, { name: "topics/a", transport: "rest" })),
      "unsettled",
    );
    advance(SETTLE);
    read("topics/a", NOT_FOUND);
    assert.equal(
      refusal(() => beginCreate(state, { name: "topics/a", transport: "rest" })),
      "unsettled",
      "a 404 does not settle a create, however late",
    );
    read("topics/a", OK);
    assert.doesNotThrow(
      () => create("topics/a", CONFLICT),
      "settled present: the name may be created again",
    );
    assert.equal(isOwned(state, "topics/a"), true);
  });

  it("keeps a name owned after a definite refusal of its delete, and allows another delete", () => {
    create("jobs/a", OK);
    assert.equal(remove("jobs/a", CONFLICT).class, "conflict");
    assert.equal(isOwned(state, "jobs/a"), true);
    assert.equal(closureReport(state).closureReady, false);
    assert.equal(remove("jobs/a", OK).class, "ok");
    read("jobs/a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
  });

  it("does not treat a 404 for a confirmed create as gone: it stays open until the A2 read-back", () => {
    create("topics/a", OK);
    assert.equal(remove("topics/a", NOT_FOUND).class, "notFound");
    assert.equal(isOwned(state, "topics/a"), true);
    let report = closureReport(state);
    assert.equal(report.closureReady, false);
    assert.deepEqual(report.reasons, [
      "owned-not-deleted:topics/a",
      "confirmed-create-reads-404:topics/a",
    ]);
    assert.deepEqual(report.confirmedReadsMissing, ["topics/a"]);
    // The same for a GET that reads 404, in the run and long after.
    create("topics/b", OK);
    assert.equal(read("topics/b", NOT_FOUND), "absent");
    advance(10 * SETTLE);
    read("topics/b", NOT_FOUND);
    report = closureReport(state);
    assert.deepEqual(report.confirmedReadsMissing, ["topics/a", "topics/b"]);
    assert.equal(report.closureReady, false);
    // The run's own DELETE answered 2xx, then a 404 read, is the normal settlement.
    assert.equal(remove("topics/b", NO_CONTENT).class, "ok");
    read("topics/b", NOT_FOUND);
    remove("topics/a", NO_CONTENT);
    read("topics/a", NOT_FOUND);
    report = closureReport(state);
    assert.deepEqual(report.confirmedReadsMissing, []);
    assert.equal(report.closureReady, true);
  });

  it("has no 404 against a name settled by a read, or created again without a delete between", () => {
    create("u", TIMEOUT);
    read("u", OK);
    assert.deepEqual(closureReport(state).confirmedReadsMissing, []);
    assert.deepEqual(closureReport(state).reasons, ["owned-not-deleted:u"]);
    create("a", OK);
    read("a", NOT_FOUND);
    assert.deepEqual(closureReport(state).confirmedReadsMissing, ["a"]);
    create("a", OK); // a second 2xx create of the same name, with no delete between
    assert.deepEqual(closureReport(state).confirmedReadsMissing, []);
  });

  it("forgets a delete's read-back state and an old 404 when an unknown create of the name is settled as present", () => {
    create("a", OK);
    read("a", NOT_FOUND);
    remove("a", OK); // not read back: the name is deleted-unverified
    create("a", TIMEOUT);
    assert.equal(read("a", OK), "present");
    assert.deepEqual(closureReport(state).reasons, ["owned-not-deleted:a"]);
    assert.deepEqual(closureReport(state).deletedUnverified, []);
    assert.deepEqual(closureReport(state).confirmedReadsMissing, []);
  });

  it("starts a new confirmed create with no 404 against it", () => {
    create("topics/a", OK);
    read("topics/a", NOT_FOUND);
    assert.deepEqual(closureReport(state).confirmedReadsMissing, ["topics/a"]);
    remove("topics/a", OK);
    assert.deepEqual(closureReport(state).confirmedReadsMissing, [], "a 2xx delete resets it");
    read("topics/a", NOT_FOUND);
    create("topics/a", OK);
    const report = closureReport(state);
    assert.deepEqual(report.confirmedReadsMissing, []);
    assert.deepEqual(report.reasons, ["owned-not-deleted:topics/a"]);
    // Also when the delete was never read back before the re-create.
    read("topics/a", NOT_FOUND);
    remove("topics/a", OK);
    create("topics/a", OK);
    assert.deepEqual(closureReport(state).reasons, ["owned-not-deleted:topics/a"]);
  });

  it("keeps a 404 read of a name this run does not own out of the evidence", () => {
    read("topics/never", NOT_FOUND);
    create("topics/c", CONFLICT);
    read("topics/c", NOT_FOUND);
    assert.deepEqual(closureReport(state).confirmedReadsMissing, []);
  });

  it("lets a deleted name be created and owned again", () => {
    create("topics/a", OK);
    remove("topics/a", OK);
    create("topics/a", OK);
    assert.equal(isOwned(state, "topics/a"), true);
  });
});

describe("unknown deletes", () => {
  it("never re-sends a delete after an unknown answer, even when a GET shows the name", () => {
    create("topics/a", OK);
    assert.equal(remove("topics/a", TIMEOUT).class, "unknown");
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "unsettled",
    );
    assert.equal(read("topics/a", OK), "present");
    assert.equal(isOwned(state, "topics/a"), true);
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "unknown-delete-not-resent",
    );
    assert.equal(closureReport(state).closureReady, false);
  });

  it("forces closureReady false for any unknown delete, even after a GET found nothing past the delay", () => {
    create("topics/a", OK);
    remove("topics/a", { status: 503, bodyReadable: true });
    advance(SETTLE);
    assert.equal(read("topics/a", NOT_FOUND), "absent");
    assert.equal(isOwned(state, "topics/a"), true, "the delete's effect was never seen");
    const report = closureReport(state);
    assert.equal(report.closureReady, false);
    assert.equal(report.unknownDeletes, 1);
    assert.deepEqual(report.reasons, [
      "unsettled-delete:topics/a",
      "owned-not-deleted:topics/a",
      "unknown-delete-answers:1",
    ]);
    // Nothing the run does afterwards clears it.
    create("topics/b", OK);
    remove("topics/b", OK);
    read("topics/b", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, false);
  });

  it("refuses a delete whose operation never reads done, and keeps closure false", () => {
    create("topics/a", OK);
    const pending = { ...OK, operationPending: true };
    assert.equal(remove("topics/a", pending).reason, "operation-pending");
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "unsettled",
    );
    advance(10 * SETTLE);
    read("topics/a", NOT_FOUND);
    read("topics/a", NOT_FOUND);
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "unsettled",
    );
    assert.equal(closureReport(state).closureReady, false);
    assert.equal(closureReport(state).unknownDeletes, 1);
    // Even once an own GET shows the name, the delete is not sent again.
    read("topics/a", OK);
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "unknown-delete-not-resent",
    );
    assert.equal(closureReport(state).closureReady, false);
  });

  it("counts each unknown delete kind", () => {
    for (const [name, answer] of [
      ["t", TIMEOUT],
      ["u", { status: 200, bodyReadable: false }],
      ["r", { status: 301, bodyReadable: true }],
      ["s", { status: 500, bodyReadable: true }],
      ["b", { status: 100, bodyReadable: true }],
    ]) {
      create(name, OK);
      assert.equal(remove(name, answer).class, "unknown", name);
    }
    assert.equal(closureReport(state).unknownDeletes, 5);
    assert.deepEqual(unsettledNames(state), ["b", "r", "s", "t", "u"]);
  });

  it("does not count an unknown create as an unknown delete", () => {
    create("topics/a", TIMEOUT);
    advance(SETTLE);
    read("topics/a", NOT_FOUND);
    assert.equal(closureReport(state).unknownDeletes, 0);
    assert.equal(closureReport(state).closureReady, false, "it stays an unsettled create");
  });
});

describe("closure", () => {
  it("is ready when every create was deleted and nothing is unknown", () => {
    create("a", OK);
    create("b", OK);
    remove("a", OK);
    remove("b", NO_CONTENT);
    read("a", NOT_FOUND);
    read("b", NOT_FOUND);
    assert.deepEqual(closureReport(state), {
      closureReady: true,
      reasons: [],
      unknownDeletes: 0,
      owned: [],
      unsettled: [],
      confirmedReadsMissing: [],
      deletedUnverified: [],
      deletedButPresent: [],
      accepted: [],
      lastRequestAt: new Date(START).toISOString(),
      a2NotBefore: new Date(START + SETTLE).toISOString(),
      details: [],
      unknownAnswers: [],
      a2Required: false,
      absentUnconfirmed: [],
      coordinatorNote: null,
    });
  });

  it("is ready for a run that created nothing", () => {
    assert.equal(closureReport(state).closureReady, true, "an empty run has nothing to clean");
    assert.deepEqual(closureReport(state).reasons, []);
  });

  it("names every reason, in name order", () => {
    create("b", OK);
    create("a", TIMEOUT);
    beginCreate(state, { name: "c", transport: "rest" });
    const report = closureReport(state);
    assert.equal(report.closureReady, false);
    assert.deepEqual(report.reasons, ["unsettled-create:a", "owned-not-deleted:b", "in-flight:c"]);
    assert.deepEqual(report.owned, ["b"]);
    assert.deepEqual(report.unsettled, ["a"]);
  });
});

describe("resuming a ledger", () => {
  const path = () => join(dir, "ledger.jsonl");

  it("replays the rows to the same state", () => {
    create("a", OK);
    create("b", TIMEOUT);
    read("b", OK);
    create("c", CONFLICT);
    create("d", OK);
    remove("d", NO_CONTENT);
    closeOwnership(state);
    state = open();
    assert.equal(isOwned(state, "a"), true);
    assert.equal(isOwned(state, "b"), true);
    assert.equal(isOwned(state, "c"), false);
    assert.equal(isOwned(state, "d"), false);
    assert.deepEqual(closureReport(state).owned, ["a", "b"]);
    // Tickets continue after the replayed ones.
    const ticket = beginCreate(state, { name: "e", transport: "rest" });
    assert.equal(ticket.ticket, 6);
  });

  it("counts an intent with no answer as unknown, and writes that answer down", () => {
    beginCreate(state, { name: "a", transport: "rest" });
    create("b", OK);
    const ticket = beginDelete(state, { name: "b", transport: "rest" });
    assert.ok(ticket);
    closeOwnership(state);
    state = open();
    assert.deepEqual(unsettledNames(state), ["a", "b"]);
    assert.equal(closureReport(state).unknownDeletes, 1);
    assert.equal(isOwned(state, "a"), false);
    const rows = readLedger(path(), "run1").rows;
    const synthetic = rows.filter((r) => r.synthetic);
    assert.deepEqual(
      synthetic.map((r) => [r.name, r.action, r.class, r.reason]),
      [
        ["a", "create", "unknown", "no-answer"],
        ["b", "delete", "unknown", "no-answer"],
      ],
    );
    assert.equal(rows.find((r) => r.phase === "resume").droppedTailBytes, 0);
    const unknownAnswers = closureReport(state).unknownAnswers;
    assert.deepEqual(
      unknownAnswers.map((e) => [e.name, e.reason, e.synthetic]),
      [
        ["a", "no-answer", true],
        ["b", "no-answer", true],
      ],
      "the report says which answers were never seen",
    );
    // The settled name is ours again after a GET, as for any unknown create.
    read("a", OK);
    assert.equal(isOwned(state, "a"), true);
    // And a second resume sees the same thing.
    closeOwnership(state);
    state = open();
    assert.equal(isOwned(state, "a"), true);
    assert.equal(closureReport(state).unknownDeletes, 1);
  });

  it("drops a row that was never finished and says so", () => {
    create("a", OK);
    closeOwnership(state);
    const torn = '{"v":1,"runId":"run1","seq":3,"phase":"inte';
    appendFileSync(path(), torn);
    state = open();
    assert.equal(isOwned(state, "a"), true);
    const rows = readLedger(path(), "run1").rows;
    assert.deepEqual(
      rows.map((r) => r.phase),
      ["open", "intent", "answer", "resume"],
    );
    assert.equal(rows[3].droppedTailBytes, Buffer.byteLength(torn));
    assert.equal(readFileSync(path(), "utf8").endsWith("\n"), true);
    create("b", OK);
    assert.equal(readLedger(path(), "run1").rows.length, 6);
  });

  it("refuses another run, a corrupt row and a gap, and adopts nothing", () => {
    create("a", OK);
    closeOwnership(state);
    assert.throws(
      () => openOwnership({ path: path(), runId: "other" }),
      (error) => error.code === "foreign-run",
    );
    const text = readFileSync(path(), "utf8");
    writeFileSync(path(), text.replace('"phase":"answer"', '"phase":"bogus"'));
    assert.throws(
      () => openOwnership({ path: path(), runId: "run1" }),
      (error) => error.code === "corrupt-ledger",
    );
    writeFileSync(path(), `not json\n${text}`);
    assert.throws(
      () => openOwnership({ path: path(), runId: "run1" }),
      (error) => error.code === "corrupt-ledger",
    );
    writeFileSync(path(), text.split("\n").slice(1).join("\n"));
    assert.throws(
      () => openOwnership({ path: path(), runId: "run1" }),
      (error) => error.code === "corrupt-ledger",
    );
    writeFileSync(path(), text.replace('"v":1', '"v":2'));
    assert.throws(
      () => openOwnership({ path: path(), runId: "run1" }),
      (error) => error.code === "corrupt-ledger",
    );
    state = open("fresh.jsonl");
  });

  it("refuses a bad path or run id", () => {
    for (const runId of ["", "a b", "x".repeat(65), 5, ".hidden", undefined]) {
      assert.throws(
        () => openOwnership({ path: join(dir, "x.jsonl"), runId }),
        (error) => error.code === "bad-run-id",
        String(runId),
      );
    }
    for (const bad of ["", undefined, 5]) {
      assert.throws(
        () => openOwnership({ path: bad, runId: "r" }),
        (error) => error.code === "bad-path",
      );
    }
  });

  it("replays a delete that answered unknown as not re-sendable", () => {
    create("a", OK);
    remove("a", TIMEOUT);
    read("a", OK);
    closeOwnership(state);
    state = open();
    assert.deepEqual(mayDelete(state, "a"), {
      allowed: false,
      reason: "unknown-delete-not-resent",
    });
    assert.equal(closureReport(state).closureReady, false);
  });
});

/** Writes a ledger file from rows, as a crashed or damaged run might have left it. */
function ledgerFile(name, rows, runId = "run1") {
  const path = join(dir, name);
  const text = [{ phase: "open", settleAbsentAfterMs: SETTLE }, ...rows]
    .map((row, index) =>
      JSON.stringify({ v: 1, runId, seq: index + 1, at: "2026-09-06T10:40:00.000Z", ...row }),
    )
    .join("\n");
  writeFileSync(path, `${text}\n`);
  return path;
}

const intent = (ticket, action, name) => ({
  phase: "intent",
  ticket,
  action,
  name,
  transport: "rest",
});
const answerRow = (ticket, action, name, extra = {}) => ({
  phase: "answer",
  ticket,
  action,
  name,
  transport: "rest",
  class: "ok",
  status: 200,
  ...extra,
});

describe("what the answer classes, errors and reports expose", () => {
  it("lists the answer classes, and every class an answer can have is one of them", () => {
    assert.deepEqual([...ANSWER_CLASSES], ["ok", "conflict", "notFound", "refused", "unknown"]);
    const seen = new Set();
    for (const status of [0, 100, 200, 204, 301, 400, 404, 409, 429, 500, 600]) {
      for (const bodyReadable of [true, false]) {
        seen.add(classifyAnswer({ status, bodyReadable }).class);
      }
    }
    seen.add(classifyAnswer({ transportError: true }).class);
    assert.deepEqual([...seen].toSorted(), [...ANSWER_CLASSES].toSorted());
    assert.throws(() => {
      ANSWER_CLASSES.push("x");
    });
  });

  it("raises errors that name themselves and carry their code", () => {
    try {
      beginDelete(state, { name: "never", transport: "rest" });
      assert.fail("expected a refusal");
    } catch (error) {
      assert.equal(error.name, "OwnershipError");
      assert.ok(error instanceof Error);
      assert.equal(error.code, "not-owned");
      assert.match(error.message, /never may not be deleted: not-owned/u);
    }
  });

  it("says what each unsettled name waits for and why", () => {
    const at = new Date(START).toISOString();
    const a2 = new Date(START + SETTLE).toISOString();
    create("b", { status: 503, bodyReadable: true });
    create("a", TIMEOUT);
    create("d", OK);
    remove("d", { status: 200, bodyReadable: false });
    const entry = (name, action, reason, ticket) => ({
      name,
      action,
      ticket,
      reason,
      answeredAt: at,
      synthetic: false,
      state: `unknown-${action}-unsettled`,
      settled: false,
      settledBy: null,
      settledAt: null,
      acceptedBy: null,
      eligibleForA2At: a2,
      requiresA2: true,
      absentReads: [],
    });
    assert.deepEqual(closureReport(state).details, [
      entry("a", "create", "transport-error", 2),
      entry("b", "create", "server-error", 1),
      entry("d", "delete", "unreadable-body", 4),
    ]);
  });

  it("lists the reasons of a closure in name order, however the names were created", () => {
    for (const name of ["c", "a", "b"]) create(name, OK);
    assert.deepEqual(closureReport(state).reasons, [
      "owned-not-deleted:a",
      "owned-not-deleted:b",
      "owned-not-deleted:c",
    ]);
    assert.deepEqual(closureReport(state).owned, ["a", "b", "c"]);
    remove("b", OK);
    assert.deepEqual(closureReport(state).owned, ["a", "c"]);
  });

  it("answers the guard with in-flight while a request of that name is open", () => {
    create("a", OK);
    beginDelete(state, { name: "a", transport: "rest" });
    assert.deepEqual(mayDelete(state, "a"), { allowed: false, reason: "in-flight" });
  });

  it("writes nothing for an answer it refuses", () => {
    const ticket = beginCreate(state, { name: "a", transport: "rest" });
    recordAnswer(state, ticket, OK);
    const before = readFileSync(join(dir, "ledger.jsonl"), "utf8");
    assert.equal(
      refusal(() => recordAnswer(state, ticket, OK)),
      "stale-ticket",
    );
    assert.equal(
      refusal(() =>
        recordAnswer(state, { ticket: 9, action: "create", name: "zzz", transport: "rest" }, OK),
      ),
      "stale-ticket",
    );
    assert.equal(readFileSync(join(dir, "ledger.jsonl"), "utf8"), before);
  });

  it("records the status of a read, and the reason and class of a mismatched one", () => {
    read("a", OK);
    create("b", TIMEOUT);
    assert.equal(read("b", { ...OK, bodyName: "other" }), "unknown");
    assert.equal(read("b", { status: 503, bodyReadable: true, bodyName: "other" }), "unknown");
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows.filter(
      (row) => row.phase === "read",
    );
    assert.deepEqual(
      rows.map((row) => [row.name, row.status, row.class, row.observed, row.reason]),
      [
        ["a", 200, "ok", "present", undefined],
        ["b", 200, "unknown", "unknown", "name-mismatch"],
        ["b", 503, "unknown", "unknown", "server-error"],
      ],
    );
  });

  it("records the action of a refused delete as a delete", () => {
    refusal(() => beginDelete(state, { name: "x", transport: "rest" }));
    const guard = readLedger(join(dir, "ledger.jsonl"), "run1").rows.at(-1);
    assert.deepEqual(
      [guard.phase, guard.action, guard.name, guard.allowed],
      ["guard", "delete", "x", false],
    );
  });
});

describe("a damaged ledger", () => {
  it("refuses two intents for one name, an answer with no intent, and an answer that does not match its intent", () => {
    const open2 = (name, rows) => {
      closeOwnership(state);
      const path = ledgerFile(name, rows);
      try {
        openOwnership({ path, runId: "run1" });
        assert.fail("expected a refusal");
      } catch (error) {
        return error;
      } finally {
        state = open("fresh.jsonl");
      }
      return null;
    };
    const twice = open2("twice.jsonl", [intent(1, "create", "a"), intent(2, "create", "a")]);
    assert.equal(twice.code, "in-flight");
    assert.match(twice.message, /already in flight/u);
    assert.equal(open2("orphan.jsonl", [answerRow(1, "create", "a")]).code, "stale-ticket");
    assert.equal(
      open2("ticket.jsonl", [intent(1, "create", "a"), answerRow(2, "create", "a")]).code,
      "stale-ticket",
    );
    assert.equal(
      open2("action.jsonl", [intent(1, "create", "a"), answerRow(1, "delete", "a")]).code,
      "stale-ticket",
    );
    assert.equal(
      open2("both.jsonl", [intent(1, "create", "a"), answerRow(2, "delete", "a")]).code,
      "stale-ticket",
    );
  });

  it("refuses a row that is not an object, and says which line is not JSON", () => {
    closeOwnership(state);
    const path = join(dir, "bad.jsonl");
    writeFileSync(path, "null\n");
    assert.throws(
      () => openOwnership({ path, runId: "run1" }),
      (error) => error.code === "corrupt-ledger",
    );
    writeFileSync(path, "42\n");
    assert.throws(
      () => openOwnership({ path, runId: "run1" }),
      (error) => error.code === "corrupt-ledger",
    );
    writeFileSync(
      path,
      '{"v":1,"runId":"run1","seq":1,"at":"2026-09-06T10:40:00.000Z","phase":"open","settleAbsentAfterMs":600000}\n{broken\n',
    );
    assert.throws(
      () => openOwnership({ path, runId: "run1" }),
      (error) => error.code === "corrupt-ledger" && /line 2 is not JSON/u.test(error.message),
    );
    state = open("fresh.jsonl");
  });

  it("keeps an unknown answer without a reason unsettled, with the reason unknown", () => {
    closeOwnership(state);
    const path = ledgerFile("noreason.jsonl", [
      intent(1, "create", "a"),
      answerRow(1, "create", "a", { class: "unknown", status: null }),
      intent(2, "create", "b"),
      answerRow(2, "create", "b"),
      intent(3, "delete", "b"),
      answerRow(3, "delete", "b", { class: "unknown", status: null }),
    ]);
    state = openOwnership({ path, runId: "run1" });
    assert.deepEqual(
      closureReport(state).details.map((d) => [d.name, d.action, d.reason, d.eligibleForA2At]),
      [
        ["a", "create", "unknown", "2026-09-06T10:50:00.000Z"],
        ["b", "delete", "unknown", "2026-09-06T10:50:00.000Z"],
      ],
    );
    assert.equal(closureReport(state).unknownDeletes, 1);
  });
});

describe("the files and descriptors it uses", () => {
  const openFds = () => fs.readdirSync("/dev/fd").length;

  it("fsyncs the directory of a new ledger, and the file when it cuts a torn row", () => {
    closeOwnership(state);
    events = [];
    state = open("fresh-dir.jsonl");
    assert.deepEqual(
      events,
      ["fsync", "write", "fsync"],
      "the new file's directory entry is made durable, then the open row",
    );
    create("a", OK);
    closeOwnership(state);
    fs.appendFileSync(join(dir, "fresh-dir.jsonl"), '{"torn');
    events = [];
    state = open("fresh-dir.jsonl");
    assert.deepEqual(events, ["fsync", "write", "fsync"], "the cut, then the resume row");
  });

  it("closes what it opens", () => {
    closeOwnership(state);
    const before = openFds();
    const fresh = open("fds.jsonl");
    const fd = fresh.fd;
    closeOwnership(fresh);
    assert.equal(openFds(), before, "no descriptor is left open after a close");
    assert.throws(
      () => fs.writeSync(fd, "x"),
      (error) => error.code === "EBADF",
    );
    state = open("fds2.jsonl");
  });
});

describe("settling: presence settles an unknown answer at once, absence never settles a create", () => {
  const stillUnsettled = (name) => assert.deepEqual(unsettledNames(state), [name]);
  const entryOf = (name) => closureReport(state).unknownAnswers.find((e) => e.name === name);

  for (const [label, answer] of [
    ["a transport error", TIMEOUT],
    ["a pending operation", { ...OK, operationPending: true }],
    ["a 503", { status: 503, bodyReadable: true }],
    ["a cancelled call", { status: 499, bodyReadable: true }],
  ]) {
    it(`keeps a create answered with ${label} unsettled whenever the GET finds nothing, however late`, () => {
      create("a", answer);
      const afterDelay = [];
      for (const wait of [0, SETTLE - 1, 1, SETTLE, SETTLE]) {
        advance(wait);
        assert.equal(read("a", NOT_FOUND), "absent");
        stillUnsettled("a");
        assert.equal(isOwned(state, "a"), false);
        assert.equal(
          refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
          "unsettled",
        );
        assert.equal(
          refusal(() => beginDelete(state, { name: "a", transport: "rest" })),
          "unsettled",
        );
        const report = closureReport(state);
        assert.equal(report.closureReady, false, `after ${wait} ms more`);
        assert.deepEqual(report.reasons, [
          "unsettled-create:a",
          "unknown-create-absent-unconfirmed:a",
        ]);
        afterDelay.push(entryOf("a").absentReads.at(-1).afterDelay);
      }
      assert.deepEqual(afterDelay, [false, false, true, true, true]);
      const report = closureReport(state);
      assert.deepEqual(report.absentUnconfirmed, ["a"]);
      assert.equal(report.a2Required, true);
      assert.match(report.coordinatorNote, /accept/u);
      assert.match(report.coordinatorNote, /recovery/u);
      assert.equal(entryOf("a").state, "unknown-create-absent-unconfirmed");
      assert.equal(entryOf("a").settled, false);
      // Nothing but a present GET changes that, and then the name is ours to delete.
      assert.equal(read("a", OK), "present");
      assert.deepEqual(unsettledNames(state), []);
      assert.equal(isOwned(state, "a"), true);
      const settled = entryOf("a");
      assert.deepEqual(
        [settled.settled, settled.settledBy, settled.state, settled.absentReads.length],
        [true, "present", "settled-present", 5],
      );
      assert.equal(closureReport(state).closureReady, false, "created, not yet deleted");
      assert.equal(remove("a", NO_CONTENT).class, "ok");
      assert.equal(closureReport(state).closureReady, false, "its delete is not read back yet");
      read("a", NOT_FOUND);
      const done = closureReport(state);
      assert.equal(done.closureReady, true);
      assert.equal(
        done.a2Required,
        true,
        "the unknown answer is part of the report for the whole run",
      );
      assert.equal(done.coordinatorNote, null);
      assert.deepEqual(done.absentUnconfirmed, []);
    });
  }

  it("measures the delay from the unknown answer, not from the intent or the first GET", () => {
    const ticket = beginCreate(state, { name: "a", transport: "rest" });
    advance(SETTLE * 5);
    recordAnswer(state, ticket, TIMEOUT);
    advance(SETTLE - 1);
    read("a", NOT_FOUND);
    advance(1);
    read("a", NOT_FOUND);
    assert.deepEqual(
      entryOf("a").absentReads.map((r) => r.afterDelay),
      [false, true],
    );
    assert.equal(entryOf("a").answeredAt, new Date(START + SETTLE * 5).toISOString());
    assert.equal(entryOf("a").eligibleForA2At, new Date(START + SETTLE * 6).toISOString());
    stillUnsettled("a");
  });

  it("settles an unknown create at once when a GET shows the name", () => {
    create("a", TIMEOUT);
    assert.equal(read("a", OK), "present");
    assert.deepEqual(unsettledNames(state), []);
    assert.equal(isOwned(state, "a"), true);
  });

  it("settles an unknown delete at once when a GET shows the name, and never by absence", () => {
    create("a", OK);
    remove("a", TIMEOUT);
    advance(SETTLE - 1);
    read("a", NOT_FOUND);
    stillUnsettled("a");
    assert.equal(isOwned(state, "a"), true, "unsettled: still counted as ours");
    advance(1);
    read("a", NOT_FOUND);
    advance(10 * SETTLE);
    read("a", NOT_FOUND);
    stillUnsettled("a");
    assert.equal(isOwned(state, "a"), true);
    const record = entryOf("a");
    assert.deepEqual(
      [record.settled, record.settledBy, record.state, record.absentReads.map((r) => r.afterDelay)],
      [false, null, "unknown-delete-absent-in-run", [false, true, true]],
    );
    create("b", OK);
    remove("b", TIMEOUT);
    read("b", OK);
    stillUnsettled("a");
    assert.equal(isOwned(state, "b"), true);
    assert.equal(entryOf("b").settledBy, "present");
  });

  it("counts a GET as an own read only when its body names the name asked for (exact own read)", () => {
    create("a", TIMEOUT);
    const ask = (answer) => recordRead(state, { name: "a", transport: "rest", answer });
    assert.equal(ask({ ...OK }), "unknown", "a 2xx with no bodyName shows nothing");
    stillUnsettled("a");
    assert.equal(ask({ ...OK, bodyName: "b" }), "unknown");
    assert.equal(ask({ ...OK, bodyName: "" }), "unknown");
    stillUnsettled("a");
    assert.equal(isOwned(state, "a"), false);
    const reasons = readLedger(join(dir, "ledger.jsonl"), "run1")
      .rows.filter((r) => r.phase === "read")
      .map((r) => [r.observed, r.reason]);
    assert.deepEqual(reasons, [
      ["unknown", "missing-body-name"],
      ["unknown", "name-mismatch"],
      ["unknown", "name-mismatch"],
    ]);
    assert.equal(ask({ ...OK, bodyName: "a" }), "present");
    assert.equal(isOwned(state, "a"), true);
    // An unknown delete is settled as still there by the same exact read, not by a bare 2xx.
    create("d", OK);
    remove("d", TIMEOUT);
    recordRead(state, { name: "d", transport: "rest", answer: { ...OK } });
    stillUnsettled("d");
    recordRead(state, { name: "d", transport: "rest", answer: { ...OK, bodyName: "d" } });
    assert.deepEqual(unsettledNames(state), []);
  });

  it("keeps every unknown answer per name for the whole run, settled or not, with its A2 eligibility", () => {
    create("c", TIMEOUT);
    create("d", OK);
    advance(1000);
    remove("d", { status: 503, bodyReadable: true });
    advance(SETTLE);
    assert.equal(read("d", NOT_FOUND), "absent");
    advance(5);
    read("c", OK);
    const report = closureReport(state);
    assert.deepEqual(
      report.unknownAnswers.map((e) => [e.name, e.action, e.state, e.settledBy, e.requiresA2]),
      [
        ["c", "create", "settled-present", "present", true],
        ["d", "delete", "unknown-delete-absent-in-run", null, true],
      ],
    );
    assert.equal(
      report.unknownAnswers[1].eligibleForA2At,
      new Date(START + 1000 + SETTLE).toISOString(),
    );
    assert.equal(report.unknownAnswers[1].settledAt, null);
    assert.equal(report.unknownAnswers[0].settledAt, new Date(START + 1005 + SETTLE).toISOString());
    assert.deepEqual(
      report.details.map((d) => d.name),
      ["d"],
      "only the unsettled answer is in the unsettled details",
    );
    // The A2 read-back starts the delay after the last request, not after an earlier answer.
    assert.equal(report.lastRequestAt, new Date(START + 1005 + SETTLE).toISOString());
    assert.equal(report.a2NotBefore, new Date(START + 1005 + 2 * SETTLE).toISOString());
    assert.equal(report.a2Required, true);
    // The same list after a resume, with the same times.
    closeOwnership(state);
    state = open();
    assert.deepEqual(closureReport(state).unknownAnswers, report.unknownAnswers);
  });

  it("keeps an unknown DELETE open in the report after an absent GET past the delay, across a resume", () => {
    create("a", OK);
    remove("a", TIMEOUT);
    advance(SETTLE);
    assert.equal(read("a", NOT_FOUND), "absent");
    const check = () => {
      const report = closureReport(state);
      assert.equal(report.closureReady, false);
      assert.deepEqual(report.reasons, [
        "unsettled-delete:a",
        "owned-not-deleted:a",
        "unknown-delete-answers:1",
      ]);
      assert.equal(report.a2Required, true);
      const [entry] = report.unknownAnswers;
      assert.deepEqual(
        [entry.name, entry.action, entry.reason, entry.answeredAt, entry.requiresA2],
        ["a", "delete", "transport-error", new Date(START).toISOString(), true],
      );
      assert.equal(entry.eligibleForA2At, new Date(START + SETTLE).toISOString());
      assert.equal(entry.state, "unknown-delete-absent-in-run");
      assert.equal(entry.settled, false);
    };
    check();
    closeOwnership(state);
    state = open();
    check();
    closeOwnership(state);
    state = open();
    check();
  });

  it("takes an unknown answer of 408 or 499 on a create or a delete as unknown, not a refusal", () => {
    for (const status of [408, 499]) {
      assert.equal(create(`c${status}`, { status, bodyReadable: true }).class, "unknown");
      create(`d${status}`, OK);
      assert.equal(remove(`d${status}`, { status, bodyReadable: true }).class, "unknown");
    }
    assert.equal(closureReport(state).unknownDeletes, 2);
    assert.deepEqual(unsettledNames(state), ["c408", "c499", "d408", "d499"]);
  });
});

describe("the settle delay is a recorded, immutable, floored setting", () => {
  const path = () => join(dir, "delay.jsonl");
  const openWith = (extra = {}) =>
    openOwnership({ path: path(), runId: "run1", now: () => clock, ...extra });

  it("is written in the first row, and defaults to the 10 minutes of the A2 read-back", () => {
    closeOwnership(state);
    state = openWith();
    const [first] = readLedger(path(), "run1").rows;
    assert.deepEqual([first.phase, first.seq, first.settleAbsentAfterMs], ["open", 1, SETTLE]);
    assert.equal(SETTLE_CONST, SETTLE);
  });

  it("refuses a delay below the floor, unless the test-only flag is given", () => {
    closeOwnership(state);
    for (const short of [0, 1, SETTLE - 1]) {
      assert.throws(
        () => openWith({ settleAbsentAfterMs: short }),
        (error) => error.code === "bad-settle-delay",
        String(short),
      );
    }
    assert.equal(existsSync(path()), false, "nothing was created by a refused open");
    assert.equal(existsSync(`${path()}.lock`), false);
    state = openWith({ settleAbsentAfterMs: 0, testOnlyAllowShortSettleDelay: true });
    create("a", OK);
    remove("a", TIMEOUT);
    read("a", NOT_FOUND);
    assert.equal(
      closureReport(state).unknownAnswers[0].absentReads[0].afterDelay,
      true,
      "the short delay is the one that counts a read as late",
    );
  });

  it("refuses values that are not a safe integer, with or without the flag", () => {
    closeOwnership(state);
    for (const bad of [
      -1,
      1.5,
      "10",
      Number.NaN,
      Infinity,
      null,
      2 ** 60,
      MAX_SETTLE_DELAY_MS + 1,
    ]) {
      for (const flag of [false, true]) {
        assert.throws(
          () =>
            openWith({
              settleAbsentAfterMs: bad,
              testOnlyAllowShortSettleDelay: flag,
            }),
          (error) => error.code === "bad-settle-delay",
          `${String(bad)} ${flag}`,
        );
      }
    }
    state = open("fresh.jsonl");
  });

  it("accepts the longest delay, whose A2 time is still a date", () => {
    closeOwnership(state);
    assert.equal(MAX_SETTLE_DELAY_MS, 2 ** 51);
    state = openWith({ settleAbsentAfterMs: MAX_SETTLE_DELAY_MS });
    create("a", TIMEOUT);
    assert.equal(
      closureReport(state).details[0].eligibleForA2At,
      new Date(START + MAX_SETTLE_DELAY_MS).toISOString(),
    );
  });

  it("accepts a longer delay, records it, and uses it when the ledger is resumed without an option", () => {
    closeOwnership(state);
    state = openWith({ settleAbsentAfterMs: 3 * SETTLE });
    create("a", OK);
    remove("a", TIMEOUT);
    assert.equal(
      closureReport(state).details[0].eligibleForA2At,
      new Date(START + 3 * SETTLE).toISOString(),
    );
    closeOwnership(state);
    state = openWith();
    assert.equal(
      closureReport(state).details[0].eligibleForA2At,
      new Date(START + 3 * SETTLE).toISOString(),
    );
    advance(2 * SETTLE);
    read("a", NOT_FOUND);
    advance(SETTLE);
    read("a", NOT_FOUND);
    assert.deepEqual(
      closureReport(state).unknownAnswers[0].absentReads.map((r) => r.afterDelay),
      [false, true],
    );
  });

  it("refuses a resume with a different delay, and accepts the same one", () => {
    closeOwnership(state);
    state = openWith();
    create("a", TIMEOUT);
    closeOwnership(state);
    for (const other of [2 * SETTLE, SETTLE + 1]) {
      assert.throws(
        () => openWith({ settleAbsentAfterMs: other }),
        (error) => error.code === "settle-delay-mismatch",
        String(other),
      );
    }
    assert.throws(
      () => openWith({ settleAbsentAfterMs: 0, testOnlyAllowShortSettleDelay: true }),
      (error) => error.code === "settle-delay-mismatch",
    );
    state = openWith({ settleAbsentAfterMs: SETTLE });
    assert.deepEqual(unsettledNames(state), ["a"]);
    assert.equal(
      readLedger(path(), "run1").rows.filter((r) => r.phase === "open").length,
      1,
      "a resume does not write another open row",
    );
  });

  it("refuses a resume of a short-delay ledger without the flag", () => {
    closeOwnership(state);
    state = openWith({ settleAbsentAfterMs: 5, testOnlyAllowShortSettleDelay: true });
    closeOwnership(state);
    assert.throws(
      () => openWith(),
      (error) => error.code === "bad-settle-delay",
    );
    state = openWith({ testOnlyAllowShortSettleDelay: true });
    advance(5);
    create("a", OK);
    remove("a", TIMEOUT);
    advance(5);
    read("a", NOT_FOUND);
    assert.equal(closureReport(state).unknownAnswers[0].absentReads[0].afterDelay, true);
  });

  it("refuses a ledger whose first row is not a valid open row, or that has a second one", () => {
    closeOwnership(state);
    const text = (rows) =>
      rows
        .map((row, i) =>
          JSON.stringify({
            v: 1,
            runId: "run1",
            seq: i + 1,
            at: "2026-09-06T10:40:00.000Z",
            ...row,
          }),
        )
        .join("\n") + "\n";
    const cases = {
      none: [intent(1, "create", "a")],
      "bad delay": [{ phase: "open", settleAbsentAfterMs: "600000" }],
      "missing delay": [{ phase: "open" }],
      second: [
        { phase: "open", settleAbsentAfterMs: SETTLE },
        { phase: "open", settleAbsentAfterMs: SETTLE },
      ],
    };
    const message = {
      none: /first ledger row is not the open row/u,
      "bad delay": /no valid settle delay/u,
      "missing delay": /no valid settle delay/u,
      second: /line 2 is a second open row/u,
    };
    for (const [label, rows] of Object.entries(cases)) {
      writeFileSync(path(), text(rows));
      assert.throws(
        () => openWith(),
        (error) => error.code === "corrupt-ledger" && message[label].test(error.message),
        label,
      );
      assert.equal(existsSync(`${path()}.lock`), false, label);
    }
    state = open("fresh.jsonl");
  });

  it("treats a ledger that holds only an unfinished first row as new", () => {
    closeOwnership(state);
    writeFileSync(path(), '{"v":1,"runId":"run1","seq":1,"phase":"op');
    state = openWith();
    assert.deepEqual(
      readLedger(path(), "run1").rows.map((r) => r.phase),
      ["open"],
    );
  });
});

describe("a failed write poisons the state", () => {
  const path = () => join(dir, "flaky.jsonl");
  /** An io whose write or fsync fails once it is armed; a failed write lands half a row first. */
  function flakyIo(mode) {
    const io = {
      armed: false,
      writeSync(fd, buffer, offset, length) {
        if (io.armed && mode === "write") {
          fs.writeSync(fd, buffer, offset, Math.floor(length / 2));
          throw new Error("EIO on write");
        }
        return fs.writeSync(fd, buffer, offset, length);
      },
      fsyncSync(fd) {
        if (io.armed && mode === "fsync") throw new Error("EIO on fsync");
        return fs.fsyncSync(fd);
      },
    };
    return io;
  }
  const openFlaky = (io) => openOwnership({ path: path(), runId: "run1", io, now: () => clock });

  for (const mode of ["write", "fsync"]) {
    it(`closes the state when a ${mode} fails: every later call raises, nothing is written, the lock is released`, () => {
      closeOwnership(state);
      const io = flakyIo(mode);
      state = openFlaky(io);
      create("a", OK);
      io.armed = true;
      assert.throws(
        () => beginCreate(state, { name: "b", transport: "rest" }),
        (error) => error.message === `EIO on ${mode}`,
      );
      io.armed = false;
      const size = readFileSync(path()).length;
      const calls = [
        () => beginCreate(state, { name: "c", transport: "rest" }),
        () => beginDelete(state, { name: "a", transport: "rest" }),
        () => beginDelete(state, { name: "never", transport: "rest" }),
        () => recordRead(state, { name: "a", transport: "rest", answer: NOT_FOUND }),
        () =>
          recordAnswer(state, { ticket: 2, action: "create", name: "b", transport: "rest" }, OK),
      ];
      for (const call of calls) assert.equal(refusal(call), "ledger-failed");
      assert.equal(readFileSync(path()).length, size, "no row after the failure");
      assert.equal(existsSync(`${path()}.lock`), false, "the writer lock is released");
      closeOwnership(state); // idempotent
      // The resume never has two intents for one name.
      state = openFlaky(spyIo());
      const rows = readLedger(path(), "run1").rows;
      const intents = rows.filter((r) => r.phase === "intent" && r.name === "b");
      if (mode === "write") {
        assert.equal(intents.length, 0, "a half row is dropped");
        assert.ok(rows.find((r) => r.phase === "resume").droppedTailBytes > 0);
        assert.deepEqual(unsettledNames(state), []);
      } else {
        assert.equal(intents.length, 1);
        assert.deepEqual(unsettledNames(state), ["b"], "a whole intent with no answer is unknown");
        const synthetic = rows.find((r) => r.synthetic);
        assert.deepEqual([synthetic.name, synthetic.reason], ["b", "no-answer"]);
      }
    });
  }

  it("also fails closed when the first row of a new ledger cannot be written", () => {
    closeOwnership(state);
    const io = flakyIo("fsync");
    io.armed = true;
    assert.throws(() => openFlaky(io));
    assert.equal(existsSync(`${path()}.lock`), false);
    state = open("fresh.jsonl");
  });
});

describe("one writer at a time", () => {
  const path = () => join(dir, "single.jsonl");
  const lockPath = () => `${path()}.lock`;
  const openAt = (extra = {}) =>
    openOwnership({ path: path(), runId: "run1", now: () => clock, ...extra });

  it("refuses a second open of a ledger that is open, and allows it after the close", () => {
    closeOwnership(state);
    state = openAt();
    assert.equal(existsSync(lockPath()), true);
    assert.throws(
      () => openAt(),
      (error) => error.code === "ledger-locked",
    );
    assert.equal(existsSync(lockPath()), true, "the refused open leaves the holder's lock alone");
    create("a", OK);
    closeOwnership(state);
    assert.equal(existsSync(lockPath()), false);
    state = openAt();
    assert.equal(isOwned(state, "a"), true);
  });

  it("takes over a lock whose holder is gone, and keeps one whose holder runs", () => {
    closeOwnership(state);
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    writeFileSync(lockPath(), `${dead}\n`);
    state = openAt();
    assert.equal(readFileSync(lockPath(), "utf8").trim(), String(process.pid));
    closeOwnership(state);
    writeFileSync(lockPath(), `${process.ppid}\n`);
    assert.throws(
      () => openAt(),
      (error) => error.code === "ledger-locked",
    );
    for (const junk of ["", "not a pid\n", "0\n", "-5\n"]) {
      writeFileSync(lockPath(), junk);
      assert.throws(
        () => openAt(),
        (error) => error.code === "ledger-locked",
        JSON.stringify(junk),
      );
    }
    rmSync(lockPath());
    state = open("fresh.jsonl");
  });

  it("refuses a lock held by a process that is alive but not ours to signal, and an unreadable lock", () => {
    closeOwnership(state);
    writeFileSync(lockPath(), "1\n"); // pid 1 exists, and a signal to it is not permitted (EPERM)
    assert.throws(
      () => openAt(),
      (error) => error.code === "ledger-locked",
    );
    rmSync(lockPath());
    fs.mkdirSync(lockPath()); // a lock that cannot be read as a file
    assert.throws(
      () => openAt(),
      (error) => error.code === "ledger-locked",
    );
    rmSync(lockPath(), { recursive: true });
    state = open("fresh.jsonl");
  });

  it("passes on an error that is not a held lock", () => {
    closeOwnership(state);
    assert.throws(
      () => openOwnership({ path: join(dir, "no", "such", "dir", "x.jsonl"), runId: "run1" }),
      (error) => error.code === "ENOENT",
    );
    state = open("fresh.jsonl");
  });

  it(
    "reports a takeover it cannot do",
    { skip: process.getuid?.() === 0 && "root ignores directory permissions" },
    () => {
      closeOwnership(state);
      // A lock of a gone writer in a directory this process may not change.
      const guarded = join(dir, "guarded");
      fs.mkdirSync(guarded);
      const dead = spawnSync(process.execPath, ["-e", ""]).pid;
      writeFileSync(join(guarded, "x.jsonl.lock"), `${dead}\n`);
      fs.chmodSync(guarded, 0o555);
      try {
        assert.throws(
          () => openOwnership({ path: join(guarded, "x.jsonl"), runId: "run1" }),
          (error) => error.code === "ledger-locked" && /taken over/u.test(error.message),
        );
      } finally {
        fs.chmodSync(guarded, 0o755);
      }
      state = open("fresh.jsonl");
    },
  );

  it("releases the lock when the open itself fails", () => {
    closeOwnership(state);
    writeFileSync(
      path(),
      '{"v":1,"runId":"other","seq":1,"at":"2026-09-06T10:40:00.000Z","phase":"open","settleAbsentAfterMs":600000}\n',
    );
    assert.throws(
      () => openAt(),
      (error) => error.code === "foreign-run",
    );
    assert.equal(existsSync(lockPath()), false);
    assert.throws(
      () => openAt({ settleAbsentAfterMs: 1 }),
      (error) => error.code === "bad-settle-delay",
    );
    assert.equal(existsSync(lockPath()), false);
    state = open("fresh.jsonl");
  });
});

describe("a delete of ours settles only when an own GET reads the name as 404", () => {
  const reasons = () => closureReport(state).reasons;

  it("keeps a name open after a 2xx delete until it is read back", () => {
    create("a", OK);
    remove("a", NO_CONTENT);
    const report = closureReport(state);
    assert.equal(report.closureReady, false);
    assert.deepEqual(report.reasons, ["deleted-unverified:a"]);
    assert.deepEqual(report.deletedUnverified, ["a"]);
    assert.equal(isOwned(state, "a"), false, "it is no longer counted as owned");
    read("a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
    assert.deepEqual(closureReport(state).deletedUnverified, []);
  });

  it("counts a delete whose operation was read done like a 2xx delete", () => {
    create("a", { ...OK, operationPending: true });
    read("a", OK); // settled as created by the own read
    // The operation of the delete was polled to done: the recorder reports a plain 200.
    remove("a", OK);
    assert.deepEqual(reasons(), ["deleted-unverified:a"]);
    read("a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
  });

  it("keeps a name open when a read-back shows it again, and settles on a later 404", () => {
    create("a", OK);
    remove("a", OK);
    assert.equal(read("a", OK), "present");
    assert.deepEqual(reasons(), ["deleted-but-present:a"]);
    assert.deepEqual(closureReport(state).deletedButPresent, ["a"]);
    read("a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
    read("a", OK);
    assert.equal(closureReport(state).closureReady, false, "the last read counts");
    assert.deepEqual(reasons(), ["deleted-but-present:a"]);
  });

  it("does not count a read before the delete, an unreadable read, or a probe delete", () => {
    create("a", OK);
    read("a", NOT_FOUND); // before the delete: a lag can hide a live resource
    remove("a", OK);
    assert.deepEqual(reasons(), ["deleted-unverified:a"]);
    recordRead(state, { name: "a", transport: "rest", answer: NOT_FOUND_UNREADABLE });
    assert.equal(read("a", TIMEOUT), "unknown");
    assert.equal(
      recordRead(state, { name: "a", transport: "rest", answer: { status: 404 } }),
      "unknown",
    );
    assert.deepEqual(reasons(), ["deleted-unverified:a"]);
    assert.equal(remove("a", NOT_FOUND).class, "notFound", "a probe delete answered 404");
    assert.deepEqual(reasons(), ["deleted-unverified:a"], "a delete answer is not a read-back");
  });

  it("starts again when the name is created again, and after a second delete", () => {
    create("a", OK);
    remove("a", OK);
    read("a", NOT_FOUND);
    create("a", OK);
    assert.deepEqual(reasons(), ["owned-not-deleted:a"]);
    remove("a", OK);
    assert.deepEqual(reasons(), ["deleted-unverified:a"]);
    read("a", NOT_FOUND);
    assert.equal(closureReport(state).closureReady, true);
  });

  it("keeps the same state across a resume", () => {
    create("a", OK);
    create("b", OK);
    remove("a", OK);
    remove("b", OK);
    read("b", OK);
    const before = closureReport(state);
    closeOwnership(state);
    state = open();
    assert.deepEqual(closureReport(state), before);
    assert.deepEqual(reasons(), ["deleted-unverified:a", "deleted-but-present:b"]);
  });
});

const NOT_FOUND_UNREADABLE = { status: 404, bodyReadable: false };

describe("an unknown DELETE is never followed by a create, and a refusal changes nothing", () => {
  it("refuses a create of a name with an unknown delete, settled by a present read or not", () => {
    create("a", OK);
    remove("a", TIMEOUT);
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "unknown-delete-not-reused",
    );
    advance(SETTLE);
    read("a", NOT_FOUND);
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "unknown-delete-not-reused",
    );
    read("a", OK);
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "unknown-delete-not-reused",
    );
  });

  it("changes neither the ledger nor the unknown record when a request is refused", () => {
    create("u", TIMEOUT);
    create("d", OK);
    remove("d", TIMEOUT);
    const ledger = () => readFileSync(join(dir, "ledger.jsonl"), "utf8");
    const before = [ledger(), JSON.stringify(closureReport(state).unknownAnswers)];
    for (const call of [
      () => beginCreate(state, { name: "u", transport: "rest" }),
      () => beginCreate(state, { name: "d", transport: "rest" }),
      () =>
        recordAnswer(
          state,
          { ticket: 1, action: "create", name: "u", transport: "rest" },
          CONFLICT,
        ),
      () =>
        recordAnswer(
          state,
          { ticket: 3, action: "delete", name: "d", transport: "rest" },
          CONFLICT,
        ),
    ]) {
      assert.ok(["unsettled", "unknown-delete-not-reused", "stale-ticket"].includes(refusal(call)));
    }
    assert.deepEqual([ledger(), JSON.stringify(closureReport(state).unknownAnswers)], before);
    // A conflict on another name never touches them.
    create("x", OK);
    create("x", CONFLICT);
    assert.deepEqual(
      closureReport(state).unknownAnswers.map((e) => [e.name, e.settled]),
      [
        ["u", false],
        ["d", false],
      ],
    );
  });
});

describe("the A2 read-back starts after the last request", () => {
  it("is null until a request is made, then the delay after the last intent, answer or read", () => {
    assert.equal(closureReport(state).lastRequestAt, null);
    assert.equal(closureReport(state).a2NotBefore, null);
    create("a", TIMEOUT);
    advance(1000);
    const ticket = beginCreate(state, { name: "b", transport: "rest" });
    assert.equal(closureReport(state).lastRequestAt, new Date(START + 1000).toISOString());
    advance(2000);
    recordAnswer(state, ticket, OK);
    assert.equal(closureReport(state).lastRequestAt, new Date(START + 3000).toISOString());
    advance(5000);
    read("a", NOT_FOUND);
    const report = closureReport(state);
    assert.equal(report.lastRequestAt, new Date(START + 8000).toISOString());
    assert.equal(report.a2NotBefore, new Date(START + 8000 + SETTLE).toISOString());
    assert.ok(report.a2NotBefore > report.unknownAnswers[0].eligibleForA2At);
  });

  it("keeps the latest time when the clock steps back", () => {
    advance(5000);
    create("a", OK);
    advance(-4000);
    read("a", OK);
    create("b", OK);
    assert.equal(closureReport(state).lastRequestAt, new Date(START + 5000).toISOString());
  });

  it("is not moved by an audit row, a resume or a synthetic answer", () => {
    create("a", OK);
    beginCreate(state, { name: "b", transport: "rest" });
    advance(10_000);
    refusal(() => beginDelete(state, { name: "never", transport: "rest" }));
    closeOwnership(state);
    advance(20_000);
    state = open();
    const report = closureReport(state);
    assert.equal(report.lastRequestAt, new Date(START).toISOString());
    assert.equal(report.unknownAnswers[0].answeredAt, new Date(START + 30_000).toISOString());
  });
});

describe("accepting an unconfirmed create", () => {
  const ask = (name, ref) => acceptUnconfirmed(state, name, ref);
  const lateAbsent = (name) => {
    advance(SETTLE);
    read(name, NOT_FOUND);
  };

  it("refuses an empty or unusable reference and writes nothing", () => {
    create("a", TIMEOUT);
    lateAbsent("a");
    const before = readFileSync(join(dir, "ledger.jsonl"), "utf8");
    for (const ref of [
      "",
      "   ",
      "\n",
      undefined,
      null,
      5,
      {},
      "x\u0000y",
      "a\nb",
      "x".repeat(1025),
    ]) {
      assert.equal(
        refusal(() => ask("a", ref)),
        "bad-ledger-ref",
        JSON.stringify(ref),
      );
    }
    assert.equal(readFileSync(join(dir, "ledger.jsonl"), "utf8"), before);
    assert.equal(closureReport(state).closureReady, false);
  });

  it("refuses a name that is not an unsettled unknown create, or has no late absent read", () => {
    create("owned", OK);
    create("del", OK);
    remove("del", TIMEOUT);
    create("fresh", TIMEOUT);
    create("early", TIMEOUT);
    advance(SETTLE - 1);
    read("early", NOT_FOUND);
    advance(SETTLE);
    read("del", NOT_FOUND);
    for (const name of ["owned", "del", "never"]) {
      assert.equal(
        refusal(() => ask(name, "ledger 900")),
        "not-unconfirmed",
        name,
      );
    }
    assert.equal(
      refusal(() => ask("fresh", "ledger 900")),
      "absent-read-required",
      "no read at all",
    );
    assert.equal(
      refusal(() => ask("early", "ledger 900")),
      "absent-read-required",
      "only a read before the delay",
    );
    assert.equal(
      refusal(() => ask("", "ledger 900")),
      "bad-name",
    );
  });

  it("lets closureReady drop only that name, records the reference, and the name is never created again", () => {
    create("a", TIMEOUT);
    create("b", TIMEOUT);
    lateAbsent("a");
    read("b", NOT_FOUND);
    ask("a", " owner ledger 901: run r, name a, reads 7 and 9 ");
    let report = closureReport(state);
    assert.equal(report.closureReady, false, "b is still unconfirmed");
    assert.deepEqual(report.unsettled, ["b"]);
    assert.deepEqual(report.absentUnconfirmed, ["b"]);
    assert.deepEqual(report.reasons, ["unsettled-create:b", "unknown-create-absent-unconfirmed:b"]);
    assert.deepEqual(report.accepted, [
      {
        name: "a",
        ledgerRef: " owner ledger 901: run r, name a, reads 7 and 9 ",
        at: new Date(START + SETTLE).toISOString(),
      },
    ]);
    const entry = report.unknownAnswers.find((e) => e.name === "a");
    assert.deepEqual(
      [entry.settled, entry.settledBy, entry.state, entry.acceptedBy],
      [true, "accepted", "settled-accepted", " owner ledger 901: run r, name a, reads 7 and 9 "],
    );
    assert.equal(isOwned(state, "a"), false);
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "accepted-unconfirmed-not-reused",
    );
    assert.equal(
      refusal(() => beginDelete(state, { name: "a", transport: "rest" })),
      "not-owned",
    );
    assert.equal(
      refusal(() => ask("a", "ledger 902")),
      "not-unconfirmed",
      "a name is accepted once",
    );
    lateAbsent("b");
    ask("b", "ledger 901");
    report = closureReport(state);
    assert.equal(report.closureReady, true);
    assert.equal(report.a2Required, true, "an acceptance does not replace the A2 read-back");
    assert.deepEqual(report.absentUnconfirmed, []);
    assert.equal(report.coordinatorNote, null);
  });

  it("is a ledger row that a resume replays, and a stray acceptance row corrupts the ledger", () => {
    create("a", TIMEOUT);
    lateAbsent("a");
    ask("a", "ledger 901");
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows;
    const row = rows.at(-1);
    assert.deepEqual(
      [row.phase, row.name, row.ledgerRef, row.ticket],
      ["accept", "a", "ledger 901", 1],
    );
    const before = closureReport(state);
    closeOwnership(state);
    state = open();
    assert.deepEqual(closureReport(state), before);
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "accepted-unconfirmed-not-reused",
    );
    closeOwnership(state);
    const path = ledgerFile("stray.jsonl", [
      intent(1, "create", "a"),
      answerRow(1, "create", "a"),
      { phase: "accept", name: "a", ticket: 1, ledgerRef: "x" },
    ]);
    assert.throws(
      () => openOwnership({ path, runId: "run1" }),
      (error) => error.code === "corrupt-ledger" && /acceptance of a/u.test(error.message),
    );
    state = open("fresh.jsonl");
  });

  it("is refused by a closed or failed state, before anything else is judged", () => {
    create("a", TIMEOUT);
    lateAbsent("a");
    closeOwnership(state);
    assert.equal(
      refusal(() => ask("a", "ledger 901")),
      "closed",
    );
    assert.equal(
      refusal(() => ask("a", "")),
      "closed",
    );
    assert.equal(
      refusal(() => ask("nobody", "ledger 901")),
      "closed",
    );
    state = open("second.jsonl");
  });
});
