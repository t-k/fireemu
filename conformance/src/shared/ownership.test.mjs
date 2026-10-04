import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import * as fs from "node:fs";

import {
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
  return openOwnership({ path: join(dir, name), runId, io: spyIo(), now: () => 1_788_000_000_000 });
}

function create(name, answer, transport = "rest") {
  const ticket = beginCreate(state, { name, transport });
  return recordAnswer(state, ticket, answer);
}

function remove(name, answer, transport = "rest") {
  const ticket = beginDelete(state, { name, transport });
  return recordAnswer(state, ticket, answer);
}

function read(name, answer, transport = "rest") {
  return recordRead(state, { name, transport, answer });
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
    [{ status: 499, bodyReadable: true }, "refused", undefined],
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
    assert.equal(afterIntent.length, 1);
    assert.deepEqual(
      {
        phase: afterIntent[0].phase,
        action: afterIntent[0].action,
        name: afterIntent[0].name,
        transport: afterIntent[0].transport,
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
      ["intent", "answer"],
    );
    assert.equal(rows[1].class, "ok");
    assert.equal(rows[1].status, 200);
    assert.equal(rows[1].transport, "rest");
    assert.equal(rows[1].name, "topics/a");
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
      ["intent", "answer", "intent", "answer", "read", "guard"],
    );
    assert.equal(rows.at(-1).allowed, false);
    assert.equal(rows.at(-1).reason, "not-owned");
  });

  it("numbers rows from 1 and stamps the run and the time", () => {
    create("topics/a", OK);
    const rows = readLedger(join(dir, "ledger.jsonl"), "run1").rows;
    assert.deepEqual(
      rows.map((r) => r.seq),
      [1, 2],
    );
    assert.ok(rows.every((r) => r.runId === "run1" && r.v === 1));
    assert.ok(rows.every((r) => r.at === new Date(1_788_000_000_000).toISOString()));
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
    assert.equal(readFileSync(join(dir, "ledger.jsonl"), "utf8"), "", "nothing was written");
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

  it("a failed or short write is an error, never a silent success", () => {
    closeOwnership(state);
    state = openOwnership({
      path: join(dir, "broken.jsonl"),
      runId: "run1",
      io: { writeSync: () => 0, fsyncSync: () => {} },
    });
    assert.equal(
      refusal(() => beginCreate(state, { name: "a", transport: "rest" })),
      "ledger-write",
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
    assert.equal(readLedger(join(dir, "chunks.jsonl"), "run1").rows.length, 2);
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
    assert.equal(closureReport(state).closureReady, true);
  });

  it("does not own an unknown create when the GET shows the name absent", () => {
    create("topics/a", TIMEOUT);
    assert.equal(read("topics/a", NOT_FOUND), "absent");
    assert.equal(isOwned(state, "topics/a"), false);
    assert.deepEqual(unsettledNames(state), []);
    assert.equal(
      refusal(() => beginDelete(state, { name: "topics/a", transport: "rest" })),
      "not-owned",
    );
    assert.equal(closureReport(state).closureReady, true, "nothing of ours is left");
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
    read("topics/a", NOT_FOUND);
    assert.doesNotThrow(
      () => create("topics/a", OK),
      "settled absent: the name may be created again",
    );
    assert.equal(isOwned(state, "topics/a"), true);
  });

  it("keeps a name owned after a definite refusal of its delete, and allows another delete", () => {
    create("jobs/a", OK);
    assert.equal(remove("jobs/a", CONFLICT).class, "conflict");
    assert.equal(isOwned(state, "jobs/a"), true);
    assert.equal(closureReport(state).closureReady, false);
    assert.equal(remove("jobs/a", OK).class, "ok");
    assert.equal(closureReport(state).closureReady, true);
  });

  it("treats a delete that answered 404 as gone", () => {
    create("topics/a", OK);
    assert.equal(remove("topics/a", NOT_FOUND).class, "notFound");
    assert.equal(isOwned(state, "topics/a"), false);
    assert.equal(closureReport(state).closureReady, true);
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

  it("forces closureReady false for any unknown delete, even one a GET settled as gone", () => {
    create("topics/a", OK);
    remove("topics/a", { status: 503, bodyReadable: true });
    assert.equal(read("topics/a", NOT_FOUND), "absent");
    assert.equal(isOwned(state, "topics/a"), false);
    const report = closureReport(state);
    assert.equal(report.closureReady, false);
    assert.equal(report.unknownDeletes, 1);
    assert.deepEqual(report.reasons, ["unknown-delete-answers:1"]);
    // Nothing the run does afterwards clears it.
    create("topics/b", OK);
    remove("topics/b", OK);
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
    read("topics/a", NOT_FOUND);
    assert.equal(closureReport(state).unknownDeletes, 0);
    assert.equal(closureReport(state).closureReady, true);
  });
});

describe("closure", () => {
  it("is ready when every create was deleted and nothing is unknown", () => {
    create("a", OK);
    create("b", OK);
    remove("a", OK);
    remove("b", NO_CONTENT);
    assert.deepEqual(closureReport(state), {
      closureReady: true,
      reasons: [],
      unknownDeletes: 0,
      owned: [],
      unsettled: [],
      details: [],
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
      ["intent", "answer", "resume"],
    );
    assert.equal(rows[2].droppedTailBytes, Buffer.byteLength(torn));
    assert.equal(readFileSync(path(), "utf8").endsWith("\n"), true);
    create("b", OK);
    assert.equal(readLedger(path(), "run1").rows.length, 5);
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
  const text = rows
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
    create("b", { status: 503, bodyReadable: true });
    create("a", TIMEOUT);
    create("d", OK);
    remove("d", { status: 200, bodyReadable: false });
    assert.deepEqual(closureReport(state).details, [
      { name: "a", action: "create", reason: "transport-error" },
      { name: "b", action: "create", reason: "server-error" },
      { name: "d", action: "delete", reason: "unreadable-body" },
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
    writeFileSync(path, '{"v":1,"runId":"run1","seq":1,"phase":"intent"}\n{broken\n');
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
    assert.deepEqual(closureReport(state).details, [
      { name: "a", action: "create", reason: "unknown" },
      { name: "b", action: "delete", reason: "unknown" },
    ]);
    assert.equal(closureReport(state).unknownDeletes, 1);
  });
});

describe("the files and descriptors it uses", () => {
  const openFds = () => fs.readdirSync("/dev/fd").length;

  it("fsyncs the directory of a new ledger, and the file when it cuts a torn row", () => {
    closeOwnership(state);
    events = [];
    state = open("fresh-dir.jsonl");
    assert.deepEqual(events, ["fsync"], "the new file's directory entry is made durable");
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
    closeOwnership(fresh);
    assert.equal(openFds(), before, "no descriptor is left open after a close");
    assert.throws(
      () => fs.writeSync(fresh.fd, "x"),
      (error) => error.code === "EBADF",
    );
    state = open("fds2.jsonl");
  });
});
