import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEFINITIVE_CODES,
  collectionOf,
  createLedger,
  isDefinitiveRefusal,
  settleNames,
} from "./fs-listen/native-ledger.mjs";

const ROOT = "projects/p/databases/(default)/documents";
const RUN = "r1";
const N = (suffix) => `${ROOT}/lsn/${RUN}-${suffix}`;
const upd = (name) => ({ update: { name } });
const del = (name) => ({ delete: name });

test("isDefinitiveRefusal separates 'not applied' codes from unknown ones", () => {
  for (const code of [3, 5, 6, 7, 8, 9, 11, 12, 16])
    assert.equal(isDefinitiveRefusal({ code }), true, `${code}`);
  for (const code of [0, 1, 2, 4, 10, 13, 14, 15, undefined, "3"])
    assert.equal(isDefinitiveRefusal({ code }), false, `${code}`);
  assert.equal(isDefinitiveRefusal(undefined), false);
  assert.equal(isDefinitiveRefusal(new Error("x")), false);
  assert.deepEqual(
    [...DEFINITIVE_CODES].toSorted((a, b) => a - b),
    [3, 5, 6, 7, 8, 9, 11, 12, 16],
  );
});

test("the ledger records what each answer says about a name", () => {
  const ledger = createLedger();
  assert.deepEqual(ledger.entries(), []);
  ledger.answered([upd(N("a")), del(N("b"))], "ok");
  assert.deepEqual(Object.fromEntries(ledger.entries()), {
    [N("a")]: { present: true, unknownDelete: false },
    [N("b")]: { present: false, unknownDelete: false },
  });
  ledger.answered([del(N("a"))], "ok");
  assert.equal(Object.fromEntries(ledger.entries())[N("a")].present, false);
  // An unknown update leaves the name unknown; an unknown delete is sticky.
  ledger.answered([upd(N("d"))], "unknown");
  ledger.answered([del(N("e"))], "unknown");
  const now = Object.fromEntries(ledger.entries());
  assert.deepEqual(now[N("d")], { present: "unknown", unknownDelete: false });
  assert.deepEqual(now[N("e")], { present: "unknown", unknownDelete: true });
  ledger.answered([del(N("e"))], "ok");
  assert.deepEqual(Object.fromEntries(ledger.entries())[N("e")], {
    present: false,
    unknownDelete: true,
  });
  // An update after an unknown update that is then confirmed is present again.
  ledger.answered([upd(N("d"))], "ok");
  assert.equal(Object.fromEntries(ledger.entries())[N("d")].present, true);
  // entries() hands out copies, in the order the names were first answered.
  ledger.entries()[0][1].present = "x";
  assert.notEqual(ledger.entries()[0][1].present, "x");
  assert.deepEqual(
    ledger.entries().map(([name]) => name),
    [N("a"), N("b"), N("d"), N("e")],
  );
});

test("collectionOf gives the collection and its parent path", () => {
  assert.deepEqual(collectionOf(`${ROOT}/lsn/x`, ROOT), { parent: ROOT, collectionId: "lsn" });
  assert.deepEqual(collectionOf(`${ROOT}/lsn/g1/child/x`, ROOT), {
    parent: `${ROOT}/lsn/g1`,
    collectionId: "child",
  });
});

/** In-memory documents with a log; `listing` is what the prefix listing answers. */
function world({ docs = [], listing = {} } = {}) {
  const present = new Set(docs);
  const log = { commits: [], lists: [], reads: [] };
  const client = {
    async missing(names) {
      log.reads.push(names.length);
      return names.map((name) => ({ name, exists: present.has(name) }));
    },
    async commit({ writes }) {
      log.commits.push(writes.map((w) => w.delete));
      if (client.commitFails) throw client.commitFails;
      if (!client.keep) for (const w of writes) present.delete(w.delete);
    },
    async listIds(request) {
      log.lists.push(request);
      return listing[`${request.parent}|${request.collectionId}`] ?? [];
    },
  };
  return { client, present, log };
}
const settle = (issued, w) => settleNames({ issued, client: w.client, root: ROOT, run: RUN });
const st = (present, unknownDelete = false) => ({ present, unknownDelete });

test("a name the run created is deleted and read back missing: complete", async () => {
  const w = world({ docs: [N("a"), N("b")] });
  const report = await settle(
    [
      [N("a"), st(true)],
      [N("b"), st(true)],
    ],
    w,
  );
  assert.deepEqual(report, {
    complete: true,
    deleted: 2,
    stillPresent: [],
    unsettled: [],
    unknownDeletes: [],
    strays: [],
    unexpectedPresent: [],
    checked: 2,
  });
  assert.equal(w.present.size, 0);
  assert.deepEqual(w.log.commits, [[N("a"), N("b")]]);
});

test("a name only a read shows is ours only if the run issued it; an issued name read present is deleted even when its create was unknown", async () => {
  const w = world({ docs: [N("a")] });
  const report = await settle([[N("a"), st("unknown")]], w);
  assert.equal(report.complete, true);
  assert.equal(report.deleted, 1);
  assert.equal(w.present.size, 0);
});

test("an unknown create that reads as missing stays unsettled: absence alone settles nothing", async () => {
  const w = world();
  const report = await settle([[N("a"), st("unknown")]], w);
  assert.equal(report.complete, false);
  assert.deepEqual(report.unsettled, [N("a")]);
  assert.deepEqual(w.log.commits, []);
});

test("a name whose delete was confirmed but that is present again is reported, not deleted", async () => {
  const w = world({ docs: [N("a")] });
  const report = await settle([[N("a"), st(false)]], w);
  assert.equal(report.complete, false);
  assert.deepEqual(report.unexpectedPresent, [N("a")]);
  assert.deepEqual(report.stillPresent, [N("a")]);
  assert.deepEqual(w.log.commits, []);
  assert.equal(w.present.size, 1);
});

test("a refused create that left nothing is complete; an unknown delete is sticky even when the name reads gone", async () => {
  const w = world();
  assert.equal((await settle([[N("a"), st(false)]], w)).complete, true);
  const sticky = await settle([[N("a"), st("unknown", true)]], world());
  assert.equal(sticky.complete, false);
  assert.deepEqual(sticky.unknownDeletes, [N("a")]);
  assert.deepEqual(sticky.unsettled, [N("a")]);
  const settledButSticky = await settle([[N("a"), st(false, true)]], world());
  assert.equal(settledButSticky.complete, false);
  assert.deepEqual(settledButSticky.unknownDeletes, [N("a")]);
  assert.deepEqual(settledButSticky.unsettled, []);
});

test("a delete the backend refuses leaves the name present: incomplete, and a definite refusal is not sticky", async () => {
  const w = world({ docs: [N("a")] });
  w.client.keep = true;
  w.client.commitFails = Object.assign(new Error("denied"), { code: 7 });
  const report = await settle([[N("a"), st(true)]], w);
  assert.equal(report.complete, false);
  assert.deepEqual(report.stillPresent, [N("a")]);
  assert.deepEqual(report.unknownDeletes, []);
});

test("a delete whose answer is unknown is sticky for the names in its batch", async () => {
  const w = world({ docs: [N("a"), N("b")] });
  w.client.commit = async ({ writes }) => {
    for (const write of writes) w.present.delete(write.delete);
    throw Object.assign(new Error("deadline"), { code: 4 });
  };
  const report = await settle(
    [
      [N("a"), st(true)],
      [N("b"), st(true)],
    ],
    w,
  );
  assert.deepEqual(report.unknownDeletes, [N("a"), N("b")]);
  assert.equal(report.complete, false);
  assert.equal(w.present.size, 0, "the deletes did land; only the answer was lost");
  assert.deepEqual(report.stillPresent, []);
});

test("strays: run-prefixed names in the run's collections that it never issued are reported and left alone", async () => {
  const stray = N("zz");
  const w = world({ docs: [N("a"), stray], listing: { [`${ROOT}|lsn`]: [N("a"), stray] } });
  const report = await settle([[N("a"), st(true)]], w);
  assert.deepEqual(report.strays, [stray]);
  assert.equal(report.complete, false);
  assert.ok(w.present.has(stray), "a stray is not deleted: nothing confirmed it is ours");
  assert.deepEqual(w.log.lists, [{ parent: ROOT, collectionId: "lsn", prefix: RUN }]);
});

test("each distinct collection is listed once, including a nested one", async () => {
  const nested = `${ROOT}/lsn/${RUN}-g1/child/${RUN}-c1`;
  const w = world({ docs: [N("a"), N("b"), nested] });
  await settle(
    [
      [N("a"), st(true)],
      [N("b"), st(true)],
      [nested, st(true)],
    ],
    w,
  );
  assert.deepEqual(
    w.log.lists.map((l) => [l.parent, l.collectionId]),
    [
      [ROOT, "lsn"],
      [`${ROOT}/lsn/${RUN}-g1`, "child"],
    ],
  );
});

test("deletes go in batches of at most 100, and 100 is one batch", async () => {
  for (const [count, batches] of [
    [100, [100]],
    [101, [100, 1]],
    [230, [100, 100, 30]],
    [0, []],
  ]) {
    const names = Array.from({ length: count }, (_, i) => N(`d${i}`));
    const w = world({ docs: names });
    const report = await settle(
      names.map((n) => [n, st(true)]),
      w,
    );
    assert.deepEqual(
      w.log.commits.map((c) => c.length),
      batches,
      `${count}`,
    );
    assert.equal(report.checked, count);
    assert.equal(report.complete, true);
  }
});

test("an incomplete read-back stops the cleanup instead of reading as absent", async () => {
  const w = world({ docs: [N("a")] });
  w.client.missing = async () => {
    throw new Error("a BatchGetDocuments answer did not mention a requested name");
  };
  await assert.rejects(settle([[N("a"), st(true)]], w), /did not mention/);
});

// A model check: for random ledgers and remote contents, only names that are issued, read present
// and not already confirmed deleted are ever deleted, and `complete` holds exactly when nothing is
// left over.
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("random ledgers: the deletes and the verdict follow the rules", async () => {
  for (let seed = 1; seed <= 300; seed += 1) {
    const random = prng(seed);
    const count = 1 + Math.floor(random() * 6);
    const issued = [];
    const docs = [];
    for (let i = 0; i < count; i += 1) {
      const name = N(`n${i}`);
      const present = [true, false, "unknown"][Math.floor(random() * 3)];
      const unknownDelete = random() < 0.2;
      issued.push([name, st(present, unknownDelete)]);
      if (random() < 0.5) docs.push(name);
    }
    const strayCount = random() < 0.3 ? 1 : 0;
    const stray = N("stray");
    if (strayCount) docs.push(stray);
    const w = world({ docs, listing: strayCount ? { [`${ROOT}|lsn`]: [stray] } : {} });
    const initial = new Set(docs);
    const report = await settle(issued, w);
    const deleted = new Set(w.log.commits.flat());
    for (const name of deleted) {
      const entry = issued.find(([n]) => n === name);
      assert.ok(entry, `seed ${seed}: only issued names are deleted`);
      assert.notEqual(entry[1].present, false, `seed ${seed}: a confirmed delete is not repeated`);
      assert.ok(initial.has(name), `seed ${seed}: only names read present are deleted`);
    }
    for (const [name, s] of issued)
      if (initial.has(name) && s.present !== false)
        assert.ok(deleted.has(name), `seed ${seed}: ${name} is deleted`);
    const leftover =
      issued.some(([name, s]) => s.present === false && initial.has(name)) ||
      issued.some(([name, s]) => s.present === "unknown" && !initial.has(name)) ||
      issued.some(([, s]) => s.unknownDelete) ||
      strayCount > 0;
    assert.equal(report.complete, !leftover, `seed ${seed}`);
    assert.ok(w.present.has(stray) === strayCount > 0, `seed ${seed}: a stray is never deleted`);
  }
});

/** A journal that keeps its lines in memory. */
const memoryJournal = () => {
  const lines = [];
  return { lines, append: (record) => lines.push(record), close() {} };
};

test("a Commit is journaled before it is sent and again with its answer; a refusal is journaled but issues no name", () => {
  const journal = memoryJournal();
  const ledger = createLedger({ journal });
  const writes = [upd(N("a")), del(N("b"))];
  ledger.sending(writes);
  assert.deepEqual(journal.lines, [
    {
      type: "names",
      phase: "before",
      names: [
        { name: N("a"), op: "create" },
        { name: N("b"), op: "delete" },
      ],
    },
  ]);
  assert.deepEqual(ledger.entries(), [], "sending issues nothing yet");
  ledger.answered(writes, "unknown");
  assert.equal(journal.lines.at(-1).phase, "after");
  assert.equal(journal.lines.at(-1).outcome, "unknown");
  const refused = createLedger({ journal });
  refused.answered([upd(N("c"))], "refused");
  assert.equal(journal.lines.at(-1).outcome, "refused");
  assert.deepEqual(refused.entries(), []);
});

test("the cleanup journals each delete batch before and after, with the answer", async () => {
  for (const [failure, outcome] of [
    [undefined, "ok"],
    [Object.assign(new Error("x"), { code: 3 }), "refused"],
    [Object.assign(new Error("x"), { code: 14 }), "unknown"],
  ]) {
    const w = world({ docs: [N("a")] });
    w.client.commitFails = failure;
    const journal = memoryJournal();
    await settleNames({
      issued: [[N("a"), st(true)]],
      client: w.client,
      root: ROOT,
      run: RUN,
      journal,
    });
    assert.deepEqual(
      journal.lines.map((line) => [line.phase, line.outcome]),
      [
        ["before", undefined],
        ["after", outcome],
      ],
    );
    assert.deepEqual(journal.lines[0].names, [{ name: N("a"), op: "delete" }]);
  }
});
