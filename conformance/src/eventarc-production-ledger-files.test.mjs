import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ledgerFilesOf, readLedgerFiles } from "./eventarc-production/ledger-files.mjs";

const RUN = "0123456789ab";
const NAME = `projects/p/locations/us-central1/channels/fe${RUN}-x`;
const OTHER = `projects/p/locations/us-central1/channels/fe${RUN}-y`;

const sent = (name, action) => ({ phase: "sent", name, action, transport: "rest" });
const answered = (name, action, kind) => ({
  phase: "answered",
  name,
  action,
  transport: "rest",
  kind,
});
const lines = (items) => `${items.map((item) => JSON.stringify(item)).join("\n")}\n`;

function directory(t) {
  const dir = mkdtempSync(join(tmpdir(), "eventarc-ledger-files-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("a run's ledger files are its own first, then the later runs' in the order of their times, and nothing else", (t) => {
  const dir = directory(t);
  for (const name of [
    `issued-${RUN}-a2-20261005T230000Z.jsonl`,
    `issued-${RUN}.jsonl`,
    `issued-${RUN}-a2-20261005T100000Z.jsonl`,
    `issued-ffffffffffff.jsonl`,
    `issued-ffffffffffff-a2-20261005T100000Z.jsonl`,
    `issued-${RUN}-a2-bad.jsonl`,
    `capture-${RUN}.jsonl`,
    `issued-${RUN}-a2-20261005T100000Z.json`,
  ])
    writeFileSync(join(dir, name), "");
  assert.deepEqual(
    ledgerFilesOf(dir, RUN).map((path) => path.slice(dir.length + 1)),
    [
      `issued-${RUN}.jsonl`,
      `issued-${RUN}-a2-20261005T100000Z.jsonl`,
      `issued-${RUN}-a2-20261005T230000Z.jsonl`,
    ],
  );
  mkdirSync(join(dir, "sub"));
  assert.deepEqual(ledgerFilesOf(join(dir, "sub"), RUN).length, 1);
});

test("a request sent and never answered is unknown, for a creation and for a deletion, and nothing stays open", (t) => {
  const dir = directory(t);
  const path = join(dir, "own.jsonl");
  writeFileSync(
    path,
    lines([
      sent(NAME, "create"),
      sent(OTHER, "create"),
      answered(OTHER, "create", "ok"),
      sent(OTHER, "delete"),
    ]),
  );
  const { ledger } = readLedgerFiles([path]);
  const state = ledger.state();
  assert.deepEqual(
    [state.get(NAME).creates, state.get(NAME).deletes, state.get(NAME).open],
    [["unknown"], [], []],
  );
  assert.deepEqual(
    [state.get(OTHER).creates, state.get(OTHER).deletes, state.get(OTHER).open],
    [["ok"], ["unknown"], []],
  );
});

test("only a deletion the later runs sent is reported as deleted by a later run", (t) => {
  const dir = directory(t);
  const own = join(dir, "own.jsonl");
  const later = join(dir, "later.jsonl");
  writeFileSync(
    own,
    lines([sent(NAME, "delete"), answered(NAME, "delete", "unknown"), sent(OTHER, "create")]),
  );
  // The later run sent a deletion of OTHER, only answered one of NAME (a line of its own run's
  // deletion is not a later run's), and sent a creation that is not a deletion.
  writeFileSync(
    later,
    lines([
      answered(NAME, "delete", "ok"),
      sent(OTHER, "create"),
      sent(OTHER, "delete"),
      answered(OTHER, "delete", "unknown"),
    ]),
  );
  const { deletedByLater } = readLedgerFiles([own, later]);
  assert.deepEqual([...deletedByLater], [OTHER]);
  // Alone, the first file is the recording itself: its own deletion is not "by a later run".
  assert.deepEqual([...readLedgerFiles([own]).deletedByLater], []);
  // A later run's creation alone is not a deletion.
  const createOnly = join(dir, "create-only.jsonl");
  writeFileSync(createOnly, lines([sent(NAME, "create"), answered(NAME, "create", "ok")]));
  assert.deepEqual([...readLedgerFiles([own, createOnly]).deletedByLater], []);
});
