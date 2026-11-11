import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createJournal, writeExclusive } from "./journal.mjs";

test("journal is exclusive, private, durable and closed", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-journal-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, "capture"),
    file = path.join(dir, "capture-abcdef123456.jsonl");
  const journal = createJournal(dir, "abcdef123456");
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  journal.write({ event: "test" });
  const row = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(row.n, 1);
  assert.equal(row.event, "test");
  assert.ok(Number.isFinite(Date.parse(row.at)));
  assert.throws(() => createJournal(dir, "abcdef123456"));
  journal.close();
  assert.throws(() => journal.write({}));
  const summary = path.join(dir, "summary.json");
  writeExclusive(summary, "{}");
  assert.equal(fs.statSync(summary).mode & 0o777, 0o600);
  assert.throws(() => writeExclusive(summary, "overwrite"));
});

test("the row limit refuses the next row and a closed journal says so", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-journal-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const journal = createJournal(path.join(root, "c"), "abcdef123456", { limit: 3 });
  for (let i = 0; i < 3; i += 1) journal.write({ i });
  assert.throws(() => journal.write({ i: 3 }), /row limit/);
  journal.close();
  journal.close();
  assert.throws(() => journal.write({}), /closed/);
});
