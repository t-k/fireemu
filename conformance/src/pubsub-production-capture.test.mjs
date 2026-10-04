import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  BudgetExceeded,
  OMIT_ABOVE,
  createBudget,
  createCapture,
  createFileJournal,
  sanitize,
} from "./pubsub-production/capture.mjs";

test("the budget counts each request and refuses the one after the cap, before it is sent", () => {
  const budget = createBudget(3);
  assert.equal(budget.max, 3);
  assert.deepEqual([budget.consume(), budget.consume(), budget.consume()], [1, 2, 3]);
  assert.equal(budget.used(), 3);
  assert.equal(budget.remaining(), 0);
  assert.throws(() => budget.consume(), BudgetExceeded);
  assert.equal(budget.used(), 3, "a refused request is not counted");
  assert.throws(() => budget.consume(), /budget of 3 is spent/);
  for (const bad of [0, -1, 1.5, "3", NaN, undefined, Infinity])
    assert.throws(() => createBudget(bad), /positive integer/, String(bad));
});

test("a long string is replaced by its length and digest, anywhere in the value, and short ones stay", () => {
  const long = "a".repeat(OMIT_ABOVE + 1);
  const clean = sanitize({
    data: long,
    nested: [{ data: long }, "short"],
    n: 5,
    ok: true,
    none: null,
  });
  assert.equal(clean.data.omitted.length, OMIT_ABOVE + 1);
  assert.match(clean.data.omitted.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(clean.nested[0], { data: clean.data });
  assert.equal(clean.nested[1], "short");
  assert.equal(clean.n, 5);
  assert.equal(clean.ok, true);
  assert.equal(clean.none, null);
  assert.equal(
    sanitize("a".repeat(OMIT_ABOVE)),
    "a".repeat(OMIT_ABOVE),
    "the limit itself is kept",
  );
  assert.equal(
    sanitize("a".repeat(OMIT_ABOVE + 1)).omitted.sha256,
    sanitize("a".repeat(OMIT_ABOVE + 1)).omitted.sha256,
  );
  assert.notEqual(
    sanitize("a".repeat(OMIT_ABOVE + 1)).omitted.sha256,
    sanitize("b".repeat(OMIT_ABOVE + 1)).omitted.sha256,
  );
});

test("the capture numbers the exchanges, counts them per case and writes them with a time", () => {
  const lines = [];
  const capture = createCapture({
    journal: { write: (line) => lines.push(line) },
    now: () => new Date("2026-10-05T01:02:03.456Z"),
  });
  assert.equal(capture.record({ case: "a", op: "x" }), 1);
  assert.equal(capture.record({ case: "a", op: "y" }), 2);
  assert.equal(capture.record({ case: "b", op: "z" }), 3);
  assert.equal(capture.record({ op: "no case" }), 4);
  capture.note("case-start", { case: "c" });
  assert.equal(capture.count(), 4);
  assert.deepEqual(capture.perCase(), { a: 2, b: 1 });
  assert.deepEqual(lines[0], { n: 1, at: "2026-10-05T01:02:03.456Z", case: "a", op: "x" });
  assert.deepEqual(lines[4], { at: "2026-10-05T01:02:03.456Z", note: "case-start", case: "c" });
});

test("the file journal is append-only, private, one JSON line each, and refuses an existing file", () => {
  const dir = mkdtempSync(join(tmpdir(), "pubsub-capture-"));
  const path = join(dir, "captures.jsonl");
  const journal = createFileJournal(path);
  journal.write({ a: 1 });
  journal.write({ b: "two" });
  journal.close();
  assert.deepEqual(
    readFileSync(path, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
    [{ a: 1 }, { b: "two" }],
  );
  assert.throws(() => createFileJournal(path), /EEXIST/);
});
