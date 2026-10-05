import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  NULL_JOURNAL,
  createJournal,
  issuedFromJournal,
  nameStates,
  readbackJournal,
} from "./fs-listen/journal.mjs";

const tmp = () => join(mkdtempSync(join(tmpdir(), "journal-")), "j.jsonl");

test("the journal file is created private, never overwritten, and each line is on disk when append returns", () => {
  const path = tmp();
  const journal = createJournal(path, { now: () => new Date("2026-10-05T00:00:00.000Z") });
  assert.equal(statSync(path).mode & 0o777, 0o600);
  journal.append({ type: "run", runId: "r1" });
  // Read back before close: the line is already written.
  assert.equal(
    readFileSync(path, "utf8"),
    '{"at":"2026-10-05T00:00:00.000Z","type":"run","runId":"r1"}\n',
  );
  journal.close();
  assert.throws(() => createJournal(path), /EEXIST/);
});

test("append writes then fsyncs the same descriptor, in that order, for every line", () => {
  const calls = [];
  const fs = {
    openSync: (path, flags, mode) => {
      calls.push(["open", mode]);
      return 7;
    },
    writeSync: (fd, text) => calls.push(["write", fd, text.endsWith("\n")]),
    fsyncSync: (fd) => calls.push(["fsync", fd]),
    closeSync: (fd) => calls.push(["close", fd]),
  };
  const journal = createJournal("x", { fs });
  journal.append({ type: "end" });
  journal.append({ type: "end" });
  journal.close();
  assert.deepEqual(calls, [
    ["open", 0o600],
    ["write", 7, true],
    ["fsync", 7],
    ["write", 7, true],
    ["fsync", 7],
    ["close", 7],
  ]);
});

test("the null journal accepts everything and keeps nothing", () => {
  NULL_JOURNAL.append({ type: "run" });
  NULL_JOURNAL.close();
});

const sample = [
  { type: "run", runId: "r1", kind: "sdk", project: "p", envelopeId: "E" },
  {
    type: "names",
    phase: "before",
    names: [
      { name: "n/b", op: "create" },
      { name: "n/a", op: "create" },
    ],
  },
  { type: "names", phase: "after", outcome: "unknown", names: [{ name: "n/b", op: "create" }] },
  { type: "account", phase: "before", name: "a", email: "a@example.com" },
  {
    type: "account",
    phase: "after",
    name: "a",
    email: "a@example.com",
    state: "created",
    uid: "u1",
  },
  { type: "account", phase: "before", name: "b", email: "b@example.com" },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

test("issuedFromJournal lists every name that may exist, the accounts with their uid, and whether the run ended", () => {
  const issued = issuedFromJournal(`${sample}\n`);
  assert.equal(issued.run.runId, "r1");
  assert.deepEqual(issued.names, ["n/a", "n/b"]);
  assert.deepEqual(issued.accounts, [
    { name: "a", email: "a@example.com", uid: "u1", state: "created" },
    { name: "b", email: "b@example.com" },
  ]);
  assert.equal(issued.ended, false);
  assert.equal(issuedFromJournal(`${sample}\n{"type":"end","productionRequests":3}\n`).ended, true);
});

test("issuedFromJournal refuses a journal without a run line or with an unreadable line", () => {
  assert.throws(() => issuedFromJournal(""), /names no run/);
  assert.throws(() => issuedFromJournal(`${sample}\n{broken`), /cannot be read/);
});

/** The journal of a run whose every create was confirmed (a complete 2xx) or definitively refused. */
const settledSample = [
  { type: "run", runId: "r1", kind: "sdk", project: "p", envelopeId: "E" },
  {
    type: "names",
    phase: "before",
    names: [
      { name: "n/b", op: "create" },
      { name: "n/a", op: "create" },
    ],
  },
  {
    type: "names",
    phase: "after",
    outcome: "ok",
    names: [
      { name: "n/b", op: "create" },
      { name: "n/a", op: "create" },
    ],
  },
  { type: "account", phase: "before", name: "a", email: "a@example.com" },
  {
    type: "account",
    phase: "after",
    name: "a",
    email: "a@example.com",
    state: "created",
    uid: "u1",
  },
  { type: "account", phase: "before", name: "b", email: "b@example.com" },
  { type: "account", phase: "after", name: "b", email: "b@example.com", state: "refused" },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

test("readback reads every name and looks up every account by uid and by email; it deletes nothing", async () => {
  const calls = [];
  const client = {
    missing: async (names) => {
      calls.push(["missing", names]);
      return names.map((name) => ({ name, exists: false }));
    },
  };
  const accountClient = {
    lookup: async (selector) => {
      calls.push(["lookup", selector]);
      return [];
    },
  };
  const out = await readbackJournal({ text: settledSample, client, accountClient });
  assert.equal(out.clean, true);
  assert.deepEqual(out.unconfirmed, []);
  assert.deepEqual(out.present, []);
  assert.equal(out.run, "r1");
  assert.deepEqual(calls, [
    ["missing", ["n/a", "n/b"]],
    ["lookup", { email: ["a@example.com"] }],
    ["lookup", { localId: ["u1"] }],
    ["lookup", { email: ["b@example.com"] }],
  ]);
});

test("readback is not clean when a name or an account is present, or a lookup is unreadable", async () => {
  const absent = { missing: async (names) => names.map((name) => ({ name, exists: false })) };
  const none = { lookup: async () => [] };
  const present = {
    missing: async (names) => names.map((name, i) => ({ name, exists: i === 0 })),
  };
  assert.equal(
    (await readbackJournal({ text: sample, client: present, accountClient: none })).clean,
    false,
  );
  const found = { lookup: async (s) => (s.email ? ["u"] : []) };
  assert.equal(
    (await readbackJournal({ text: sample, client: absent, accountClient: found })).clean,
    false,
  );
  const unreadable = { lookup: async (s) => (s.localId ? null : []) };
  assert.equal(
    (await readbackJournal({ text: sample, client: absent, accountClient: unreadable })).clean,
    false,
  );
});

test("a line of an unknown type never marks the run ended", () => {
  const issued = issuedFromJournal(`${sample}\n{"type":"note","text":"x"}\n`);
  assert.equal(issued.ended, false);
});

test("readback of a journal with no names reads no names, and a uid found alone makes it unclean", async () => {
  const noNames = [
    { type: "run", runId: "r1", kind: "sdk", project: "p" },
    {
      type: "account",
      phase: "after",
      name: "a",
      email: "a@example.com",
      state: "created",
      uid: "u1",
    },
  ]
    .map((r) => JSON.stringify(r))
    .join("\n");
  const calls = [];
  const client = {
    missing: async (names) => {
      calls.push(names);
      return [];
    },
  };
  const byUid = { lookup: async (selector) => (selector.localId ? ["u1"] : []) };
  const report = await readbackJournal({ text: noNames, client, accountClient: byUid });
  assert.deepEqual(calls, [], "no names, no BatchGet");
  assert.equal(report.clean, false);
  const byEmail = { lookup: async (selector) => (selector.email ? ["u1"] : []) };
  assert.equal(
    (await readbackJournal({ text: noNames, client, accountClient: byEmail })).clean,
    false,
  );
  const none = { lookup: async () => [] };
  const clean = await readbackJournal({
    text: noNames,
    client,
    accountClient: none,
    now: () => new Date("2026-10-05T10:00:00.000Z"),
  });
  assert.equal(clean.clean, true);
  assert.equal(clean.readAt, "2026-10-05T10:00:00.000Z");
});

// ---- the A2 read-back and an unknown create (checklist section 3) ----

const journalOf = (...records) =>
  [{ type: "run", runId: "r1", kind: "native", project: "p", envelopeId: "E" }, ...records]
    .map((r) => JSON.stringify(r))
    .join("\n");
const before = (...ops) => ({
  type: "names",
  phase: "before",
  names: ops.map(([name, op]) => ({ name, op })),
});
const after = (outcome, ...ops) => ({
  type: "names",
  phase: "after",
  outcome,
  names: ops.map(([name, op]) => ({ name, op })),
});
const reads = (present = []) => ({
  missing: async (names) => names.map((name) => ({ name, exists: present.includes(name) })),
});
const noAccounts = { lookup: async () => [] };
const A = ["n/a", "create"];
const D = ["n/a", "delete"];

test("an unknown create that reads 404 at A2 is unconfirmed and blocks clean; absence never settles it", async () => {
  const text = journalOf(before(A), after("unknown", A));
  const report = await readbackJournal({ text, client: reads(), accountClient: noAccounts });
  assert.equal(report.clean, false);
  assert.deepEqual(report.unconfirmed, ["n/a"]);
  assert.deepEqual(report.present, []);
  assert.deepEqual(report.names, [{ name: "n/a", exists: false }]);
});

test("an unknown create that reads present at A2 is reported present, is not clean, and nothing is deleted", async () => {
  const text = journalOf(before(A), after("unknown", A));
  const calls = [];
  const client = {
    ...reads(["n/a"]),
    commit: async () => calls.push("commit"),
    delete: async () => calls.push("delete"),
  };
  const report = await readbackJournal({ text, client, accountClient: noAccounts });
  assert.equal(report.clean, false);
  assert.deepEqual(report.present, ["n/a"]);
  assert.deepEqual(report.unconfirmed, [], "a name that reads present is present, not unconfirmed");
  assert.deepEqual(calls, []);
});

test("a confirmed create that reads 404 at A2 settles, and so does an unknown delete that reads 404", async () => {
  const confirmed = journalOf(before(A), after("ok", A));
  const one = await readbackJournal({
    text: confirmed,
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(one.clean, true);
  assert.deepEqual(one.unconfirmed, []);
  const unknownDelete = journalOf(before(A), after("ok", A), before(D), after("unknown", D));
  const two = await readbackJournal({
    text: unknownDelete,
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(two.clean, true);
  assert.deepEqual(two.unconfirmed, []);
  // The same unknown delete that still reads present is not clean.
  const three = await readbackJournal({
    text: unknownDelete,
    client: reads(["n/a"]),
    accountClient: noAccounts,
  });
  assert.equal(three.clean, false);
  assert.deepEqual(three.present, ["n/a"]);
});

test("a name journaled before and never answered (a crash in the Commit) is an unknown create", async () => {
  const text = journalOf(before(A));
  const report = await readbackJournal({ text, client: reads(), accountClient: noAccounts });
  assert.equal(report.clean, false);
  assert.deepEqual(report.unconfirmed, ["n/a"]);
});

test("an account whose create was unknown, or never answered, and that no lookup found is unconfirmed", async () => {
  const unknown = journalOf(
    { type: "account", phase: "before", name: "a", email: "a@example.com" },
    { type: "account", phase: "after", name: "a", email: "a@example.com", state: "unknown" },
  );
  const report = await readbackJournal({
    text: unknown,
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(report.clean, false);
  assert.deepEqual(report.unconfirmed, ["account:a@example.com"]);
  const pending = journalOf({
    type: "account",
    phase: "before",
    name: "a",
    email: "a@example.com",
  });
  const second = await readbackJournal({
    text: pending,
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(second.clean, false);
  assert.deepEqual(second.unconfirmed, ["account:a@example.com"]);
  // Found at A2: present (not clean), not unconfirmed.
  const found = await readbackJournal({
    text: unknown,
    client: reads(),
    accountClient: { lookup: async (s) => (s.email ? ["u9"] : []) },
  });
  assert.equal(found.clean, false);
  assert.deepEqual(found.unconfirmed, []);
  // A created account (with its uid), a refused one and one found by email settle when absent.
  for (const state of [
    { state: "created", uid: "u1" },
    { state: "refused" },
    { state: "found-by-email", uid: "u1" },
  ]) {
    const text = journalOf(
      { type: "account", phase: "before", name: "a", email: "a@example.com" },
      { type: "account", phase: "after", name: "a", email: "a@example.com", ...state },
    );
    const done = await readbackJournal({ text, client: reads(), accountClient: noAccounts });
    assert.equal(done.clean, true, JSON.stringify(state));
    assert.deepEqual(done.unconfirmed, []);
  }
});

test("nameStates: what each name's answers leave of its create", () => {
  const states = (...records) => nameStates(journalOf(...records));
  const unconfirmed = (map) => [...map].filter(([, s]) => s.unconfirmed).map(([name]) => name);
  // Refused creates apply nothing.
  assert.deepEqual(unconfirmed(states(before(A), after("refused", A))), []);
  // A later confirmed create confirms a name an earlier create left unknown.
  assert.deepEqual(
    unconfirmed(states(before(A), after("unknown", A), before(A), after("ok", A))),
    [],
  );
  // An unknown update of a confirmed name leaves it confirmed.
  assert.deepEqual(
    unconfirmed(states(before(A), after("ok", A), before(A), after("unknown", A))),
    [],
  );
  // A delete that the cleanup sent after reading the name present settles an unknown create.
  assert.deepEqual(
    unconfirmed(states(before(A), after("unknown", A), before(D), after("ok", D))),
    [],
  );
  assert.deepEqual(unconfirmed(states(before(A), after("unknown", A), before(D))), []);
  // A confirmed delete forgets the confirmation: an unknown create after it is unknown again.
  assert.deepEqual(
    unconfirmed(
      states(before(A), after("ok", A), before(D), after("ok", D), before(A), after("unknown", A)),
    ),
    ["n/a"],
  );
  // A before that is followed by another before of the same name without an answer is unknown.
  assert.deepEqual(unconfirmed(states(before(A), before(A), after("ok", A))), []);
  assert.deepEqual(unconfirmed(states(before(A), before(A))), ["n/a"]);
  // An after that names only some of the names of its before leaves the rest unanswered.
  const B = ["n/b", "create"];
  assert.deepEqual(unconfirmed(states(before(A, B), after("ok", A))), ["n/b"]);
  assert.deepEqual(unconfirmed(states(before(A, B), after("unknown", A, B))), ["n/a", "n/b"]);
  // A refused delete applies nothing: it settles nothing and forgets nothing.
  assert.deepEqual(
    unconfirmed(states(before(A), after("unknown", A), before(D), after("refused", D))),
    ["n/a"],
  );
  assert.deepEqual(
    unconfirmed(
      states(
        before(A),
        after("ok", A),
        before(D),
        after("refused", D),
        before(A),
        after("unknown", A),
      ),
    ),
    [],
  );
  // A create opened again and refused leaves the earlier unknown create as it was.
  assert.deepEqual(
    unconfirmed(states(before(A), after("unknown", A), before(A), after("refused", A))),
    ["n/a"],
  );
  assert.deepEqual(unconfirmed(states(before(A), after("unknown", A), before(A))), ["n/a"]);
  // An unknown delete forgets nothing (the name may still exist, as confirmed).
  assert.deepEqual(
    unconfirmed(
      states(
        before(A),
        after("ok", A),
        before(D),
        after("unknown", D),
        before(A),
        after("unknown", A),
      ),
    ),
    [],
  );
  // An answer of a value the journal does not define is an unknown answer, never a confirmation.
  assert.deepEqual(unconfirmed(states(before(A), after("timeout", A))), ["n/a"]);
  assert.deepEqual(unconfirmed(states(before(A), after(undefined, A))), ["n/a"]);
  // The create left open when the same name is opened again still counts when the second one is refused.
  assert.deepEqual(unconfirmed(states(before(A), before(A), after("refused", A))), ["n/a"]);
  // A line that is not JSON is refused here as it is by issuedFromJournal.
  assert.throws(() => nameStates("{broken"), /cannot be read/);
  // A maybe name is in the answer, open (unconfirmed) until a closing line.
  assert.deepEqual([...states({ ...before(A), maybe: true })], [["n/a", { unconfirmed: true }]]);
  assert.deepEqual(
    [...states({ ...before(A), maybe: true }, after("known", A))],
    [["n/a", { unconfirmed: false }]],
  );
  // Names the SDK marks `maybe` are names that may exist: open until a closing line, whatever else the journal holds.
  assert.deepEqual(unconfirmed(states({ ...before(A), maybe: true })), ["n/a"]);
  assert.deepEqual(unconfirmed(states(before(A), { ...before(B), maybe: true })).toSorted(), [
    "n/a",
    "n/b",
  ]);
  assert.deepEqual(
    unconfirmed(states(before(A), { ...before(B), maybe: true }, after("known", B))),
    ["n/a"],
  );
  // A real create left open and then listed as maybe is still an unknown create.
  assert.deepEqual(unconfirmed(states(before(B), { ...before(B), maybe: true })), ["n/b"]);
  // A maybe name answered by a confirmed create is confirmed, and a maybe after changes nothing.
  assert.deepEqual(unconfirmed(states({ ...before(B), maybe: true }, after("ok", B))), []);
  assert.deepEqual(unconfirmed(states(before(B), { ...after("unknown", B), maybe: true })), [
    "n/b",
  ]);
});

test("nameStates over random journals agrees with an event-by-event oracle", () => {
  let seed = 99;
  const next = (n) => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed % n;
  };
  for (let round = 0; round < 400; round += 1) {
    const records = [];
    // The oracle works on one name; the other name is only noise, answered ok.
    let confirmed = false;
    let unknownCreate = false;
    for (let i = 0, n = 1 + next(6); i < n; i += 1) {
      const op = next(3) === 0 ? "delete" : "create";
      const outcome = ["ok", "unknown", "refused", "none"][next(4)];
      const entry = ["n/x", op];
      records.push(before(entry, ["n/y", "create"]));
      if (outcome !== "none") records.push(after(outcome, entry), after("ok", ["n/y", "create"]));
      else records.push(after("ok", ["n/y", "create"]));
      const answer = outcome === "none" ? "unknown" : outcome;
      if (op === "create") {
        if (answer === "ok") {
          confirmed = true;
          unknownCreate = false;
        } else if (answer === "unknown" && !confirmed) unknownCreate = true;
      } else if (answer !== "refused") {
        unknownCreate = false;
        if (answer === "ok") confirmed = false;
      }
    }
    const got = nameStates(journalOf(...records));
    assert.equal(got.get("n/x").unconfirmed, unknownCreate, JSON.stringify(records));
    assert.equal(got.get("n/y").unconfirmed, false);
  }
});

test("the may-exist names of an SDK or browser run stay open until a closing line: a crash leaves them unconfirmed, known settles them, unknown does not", async () => {
  const names = [
    ["n/a", "create"],
    ["n/b", "create"],
  ];
  const account = [
    { type: "account", phase: "before", name: "a", email: "a@example.com" },
    {
      type: "account",
      phase: "after",
      name: "a",
      email: "a@example.com",
      state: "created",
      uid: "u1",
    },
    { type: "account-delete", phase: "before", uid: "u1" },
    { type: "account-delete", phase: "after", uid: "u1", outcome: "answered", settled: true },
  ];
  const opened = { ...before(...names), maybe: true };
  const closing = (outcome) => after(outcome, ...names);
  // A crash after the maybe line: no closing line and no end line.
  const crashed = await readbackJournal({
    text: journalOf(...account.slice(0, 2), opened),
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(crashed.ended, false);
  assert.equal(crashed.clean, false);
  assert.deepEqual(crashed.unconfirmed.toSorted(), ["n/a", "n/b"]);
  // Known: no write of unknown outcome; absent names settle.
  const known = await readbackJournal({
    text: journalOf(...account, opened, closing("known"), { type: "end", productionRequests: 1 }),
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(known.clean, true);
  assert.deepEqual(known.unconfirmed, []);
  // Known and present: not clean.
  const present = await readbackJournal({
    text: journalOf(...account, opened, closing("known")),
    client: reads(["n/a"]),
    accountClient: noAccounts,
  });
  assert.equal(present.clean, false);
  assert.deepEqual(present.present, ["n/a"]);
  assert.deepEqual(present.unconfirmed, []);
  // Unknown: absent names are unconfirmed.
  const unknown = await readbackJournal({
    text: journalOf(...account, opened, closing("unknown")),
    client: reads(),
    accountClient: noAccounts,
  });
  assert.equal(unknown.clean, false);
  assert.deepEqual(unknown.unconfirmed.toSorted(), ["n/a", "n/b"]);
  // A closing line for only some of the names leaves the rest open.
  const some = await readbackJournal({
    text: journalOf(...account, opened, after("known", names[0])),
    client: reads(),
    accountClient: noAccounts,
  });
  assert.deepEqual(some.unconfirmed, ["n/b"]);
});

test("nameStates: a known closing line is not a confirmation and does not touch a name that is not a may-exist name", () => {
  const unconfirmed = (...records) =>
    [...nameStates(journalOf(...records))].filter(([, s]) => s.unconfirmed).map(([name]) => name);
  const B = ["n/b", "create"];
  assert.deepEqual(unconfirmed({ ...before(A), maybe: true }), ["n/a"]);
  assert.deepEqual(unconfirmed({ ...before(A), maybe: true }, after("known", A)), []);
  assert.deepEqual(unconfirmed({ ...before(A), maybe: true }, after("unknown", A)), ["n/a"]);
  // A known line for a name that was never opened as maybe changes nothing (and is not a create answer).
  assert.deepEqual(unconfirmed(after("known", A)), []);
  assert.deepEqual(
    unconfirmed(before(A), after("known", A)),
    ["n/a"],
    "an ordinary create is not answered by known",
  );
  // A later confirmed create, or a cleanup delete, settles a name still open.
  assert.deepEqual(unconfirmed({ ...before(A), maybe: true }, before(A), after("ok", A)), []);
  assert.deepEqual(unconfirmed({ ...before(A), maybe: true }, before(D), after("ok", D)), []);
  // Unknown after known stays unknown; known after unknown does not clear it.
  assert.deepEqual(
    unconfirmed({ ...before(A), maybe: true }, after("known", A), after("unknown", A)),
    ["n/a"],
  );
  assert.deepEqual(
    unconfirmed({ ...before(A), maybe: true }, after("unknown", A), after("known", A)),
    ["n/a"],
  );
  // Names are independent.
  assert.deepEqual(unconfirmed({ ...before(A, B), maybe: true }, after("known", B)), ["n/a"]);
  // A name that is already confirmed is not opened again as a may-exist name.
  assert.deepEqual(unconfirmed(before(A), after("ok", A), { ...before(A), maybe: true }), []);
  // A name no answer touched is in the result, not unconfirmed.
  assert.deepEqual(
    [...nameStates(journalOf(before(A), after("refused", A)))],
    [["n/a", { unconfirmed: false }]],
  );
});
