import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  NULL_JOURNAL,
  createJournal,
  issuedFromJournal,
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
  const out = await readbackJournal({ text: sample, client, accountClient });
  assert.equal(out.clean, true);
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
