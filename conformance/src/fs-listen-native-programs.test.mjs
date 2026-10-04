import assert from "node:assert/strict";
import { test } from "node:test";

import {
  COLLECTION,
  NATIVE_PROGRAMS,
  SWEEP,
  programProblems,
} from "./fs-listen/native-programs.mjs";
import { cleanupNative, runNative, targetFor } from "./fs-listen/native-run.mjs";

test("the native programs are well formed", () => {
  assert.deepEqual(programProblems(NATIVE_PROGRAMS), []);
});

test("every closure condition the native programs serve is named by a program", () => {
  const named = new Set(NATIVE_PROGRAMS.flatMap((p) => p.conditions));
  for (const condition of [
    "FS-LISTEN-SDK/native-target-protocol",
    "FS-LISTEN-SDK/raw-resume-token",
    "FS-LISTEN-SDK/existence-filter-reconnect",
    "FS-LISTEN-SDK/default-subscription",
    "FS-TRANSACTION/commit-atomic-visibility",
  ])
    assert.ok(named.has(condition), condition);
});

test("programProblems reports an unopened stream, an unknown doc, a reused row and an unsaved token", () => {
  const bad = [
    {
      id: "native/bad",
      conditions: ["x"],
      docs: { a: "c/{run}-a" },
      steps: [
        { do: "wait", stream: "ghost", until: { frames: 1 } },
        { do: "seed", doc: "zz", fields: {} },
        { do: "open", stream: "s", targets: [{ id: 1, doc: "a", resume: "nope" }] },
        { do: "record", row: "native/bad/r", stream: "s" },
        { do: "record", row: "native/bad/r", stream: "s" },
        { do: "record", row: "elsewhere/r", stream: "s" },
      ],
    },
  ];
  const problems = programProblems(bad).join("\n");
  assert.match(problems, /stream ghost is not open/);
  assert.match(problems, /unknown doc zz/);
  assert.match(problems, /token nope is not saved yet/);
  assert.match(problems, /row native\/bad\/r is recorded twice/);
  assert.match(problems, /row elsewhere\/r must start with native\/bad\//);
  assert.match(problems, /stream s is never closed/);
});

test("every target the programs open builds without a saved token it does not have", () => {
  const ctxFor = (program) => ({
    root: "projects/p/databases/(default)/documents",
    run: "r",
    docs: program.docs,
    tokens: new Map([["t0", { readTime: { seconds: "1", nanos: 0 }, token: Buffer.from("x") }]]),
  });
  for (const program of NATIVE_PROGRAMS) {
    for (const step of program.steps) {
      for (const spec of step.targets ?? (step.target ? [step.target] : [])) {
        const t = { ...spec };
        // Saved names exist at run time; the builder is exercised with every name resolvable.
        const ctx = ctxFor(program);
        for (const key of ["resume", "readTimeFrom"])
          if (t[key] !== undefined)
            ctx.tokens.set(t[key], { token: Buffer.from("x"), readTime: { seconds: "1" } });
        const built = targetFor(t, ctx);
        assert.equal(built.targetId, spec.id);
        assert.ok(built.documents || built.query);
      }
    }
  }
});

test("the programs run to the end against a client that answers every wait", async () => {
  const frames = (stream) => {
    // Every stream immediately shows ADD/CURRENT for each target id it was asked for.
    const ids = [1, 2, 7, 0, -1];
    for (const id of ids)
      stream.frames.push(
        { kind: "targetChange", targetChange: { targetChangeType: "ADD", targetIds: [id] } },
        {
          kind: "targetChange",
          targetChange: {
            targetChangeType: "CURRENT",
            targetIds: [id],
            resumeToken: Buffer.from("t"),
            readTime: { seconds: "1", nanos: 0 },
          },
        },
        { kind: "targetChange", targetChange: { targetChangeType: "REMOVE", targetIds: [id] } },
        { kind: "documentChange", documentChange: { document: { name: "x" }, targetIds: [id] } },
      );
  };
  const docs = new Set();
  const client = {
    async commit() {},
    async beginTransaction() {
      return Buffer.from("tx");
    },
    openStream() {
      const stream = { frames: [], ended: () => undefined, send() {}, async close() {} };
      frames(stream);
      return stream;
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: docs.has(name) }));
    },
    async listIds() {
      return [];
    },
  };
  // A wait that no frame satisfies runs out on this clock, which only sleeping moves.
  const clock = { t: 0 };
  const out = await runNative(NATIVE_PROGRAMS, {
    client,
    project: "p",
    run: "r",
    sleep: async (ms) => {
      clock.t += ms;
    },
    now: () => clock.t,
  });
  assert.deepEqual(out.errors, {});
  const recorded = new Set(Object.keys(out.rows));
  for (const program of NATIVE_PROGRAMS)
    for (const step of program.steps)
      if (step.do === "record") assert.ok(recorded.has(step.row), step.row);
  const report = await cleanupNative(NATIVE_PROGRAMS, {
    client,
    project: "p",
    run: "r",
    sweep: [],
  });
  assert.equal(report.complete, true);
});

const prog = (steps, extra = {}) => ({
  id: "native/p",
  conditions: ["c"],
  docs: { a: "c/{run}-a", b: "c/{run}-b" },
  steps,
  ...extra,
});
const problemsOf = (...programs) => programProblems(programs);

test("programProblems: one rule at a time", () => {
  assert.deepEqual(problemsOf(prog([])), []);
  assert.match(problemsOf(prog([], { id: "other/p" }))[0], /id must start with native\//);
  assert.match(problemsOf(prog([], { conditions: [] })).join(), /names no condition/);
  assert.match(problemsOf(prog([{ do: "nope" }])).join(), /#0 \(nope\): unknown step/);
  assert.match(problemsOf(prog([{ do: "close", stream: "s" }])).join(), /stream s is not open/);
  assert.match(
    problemsOf(prog([{ do: "remove", stream: "s", id: 1 }])).join(),
    /stream s is not open/,
  );
  assert.match(
    problemsOf(prog([{ do: "add", stream: "s", target: { id: 1, doc: "a" } }])).join(),
    /stream s is not open/,
  );
  const open = { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] };
  assert.match(
    problemsOf(prog([open, open, { do: "close", stream: "s" }])).join(),
    /stream s opened twice/,
  );
  // A stream can be opened again after it was closed.
  assert.deepEqual(
    problemsOf(prog([open, { do: "close", stream: "s" }, open, { do: "close", stream: "s" }])),
    [],
  );
  assert.match(
    problemsOf(
      prog([
        open,
        { do: "add", stream: "s", target: { id: 2, doc: "zz" } },
        { do: "close", stream: "s" },
      ]),
    ).join(),
    /unknown doc zz/,
  );
  assert.deepEqual(
    problemsOf(
      prog([
        open,
        { do: "add", stream: "s", target: { id: 2, collectionGroup: "k" } },
        { do: "close", stream: "s" },
      ]),
    ),
    [],
  );
  assert.match(problemsOf(prog([{ do: "delete", doc: "zz" }])).join(), /unknown doc zz/);
  assert.match(problemsOf(prog([{ do: "write", doc: "zz", fields: {} }])).join(), /unknown doc zz/);
  assert.deepEqual(problemsOf(prog([{ do: "settle" }, { do: "sleep", ms: 1 }])), []);
});

test("programProblems: writes in a commit or a transaction name documents the program has", () => {
  assert.match(
    problemsOf(
      prog([
        {
          do: "commit",
          writes: [
            { doc: "a", fields: {} },
            { doc: "zz", fields: {} },
          ],
        },
      ]),
    ).join(),
    /unknown doc zz/,
  );
  assert.match(
    problemsOf(prog([{ do: "txn", writes: [{ delete: "zz" }] }])).join(),
    /unknown doc zz/,
  );
  assert.deepEqual(
    problemsOf(prog([{ do: "commit", writes: [{ doc: "a", fields: {} }, { delete: "b" }] }])),
    [],
  );
});

test("programProblems: a token or a read time must be saved by an earlier step, under the name used", () => {
  const open = { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] };
  const close = { do: "close", stream: "s" };
  const use = (target) => ({ do: "open", stream: "r", targets: [{ id: 1, doc: "a", ...target }] });
  const closeR = { do: "close", stream: "r" };
  const withSave = (save, target) =>
    problemsOf(prog([open, save, close, use(target), closeR])).join();
  assert.equal(withSave({ do: "save", stream: "s", id: 1, token: "t" }, { resume: "t" }), "");
  assert.equal(withSave({ do: "save", stream: "s", id: 1, time: "w" }, { readTimeFrom: "w" }), "");
  assert.equal(
    withSave(
      { do: "save", stream: "s", id: 1, token: "t", time: "w" },
      { resume: "t", readTimeFrom: "w" },
    ),
    "",
  );
  assert.equal(
    withSave({ do: "save", stream: "s", id: 1, token: "t", time: "w" }, { resume: "w" }),
    "",
  );
  assert.match(
    withSave({ do: "save", stream: "s", id: 1, token: "t" }, { resume: "x" }),
    /token x is not saved yet/,
  );
  assert.match(
    withSave({ do: "save", stream: "s", id: 1, token: "t" }, { readTimeFrom: "x" }),
    /read time x is not saved yet/,
  );
  // A save later in the program does not help an earlier open.
  assert.match(
    problemsOf(
      prog([
        use({ resume: "t" }),
        closeR,
        open,
        { do: "save", stream: "s", id: 1, token: "t" },
        close,
      ]),
    ).join(),
    /token t is not saved yet/,
  );
  assert.match(
    problemsOf(prog([{ do: "save", stream: "s", id: 1, token: "t" }])).join(),
    /stream s is not open/,
  );
});

test("programProblems: rows are named after their program and are unique across programs", () => {
  const rec = (row) => [
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "record", row, stream: "s" },
    { do: "close", stream: "s" },
  ];
  assert.deepEqual(problemsOf(prog(rec("native/p/x"))), []);
  assert.match(
    problemsOf(prog(rec("native/pp/x"))).join(),
    /row native\/pp\/x must start with native\/p\//,
  );
  assert.match(problemsOf(prog(rec("native/p"))).join(), /must start with native\/p\//);
  assert.match(
    problemsOf(prog(rec("native/p/x")), prog(rec("native/p/x"), { id: "native/p" })).join(),
    /recorded twice/,
  );
  const other = prog(rec("native/q/x"), { id: "native/q" });
  assert.deepEqual(problemsOf(prog(rec("native/p/x")), other), []);
  // Two rows of one stream are two rows; the same row twice is not.
  const twice = [
    { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
    { do: "record", row: "native/p/1", stream: "s" },
    { do: "record", row: "native/p/2", stream: "s" },
    { do: "close", stream: "s" },
  ];
  assert.deepEqual(problemsOf(prog(twice)), []);
});

test("every program owns its documents and its group, so one program's state cannot reach another's", () => {
  const templates = NATIVE_PROGRAMS.flatMap((p) => Object.values(p.docs));
  assert.equal(new Set(templates).size, templates.length);
  for (const t of templates) assert.match(t, /^lsn_native\/.*\{run\}-[a-z]+-/);
  const groupsOf = (p) =>
    new Set(
      [...JSON.stringify(p.steps).matchAll(/"g":"([^"]+)"|\["g","([^"]+)"\]/g)].map(
        (m) => m[1] ?? m[2],
      ),
    );
  const seen = new Map();
  for (const p of NATIVE_PROGRAMS)
    for (const g of groupsOf(p)) {
      if (g.endsWith("-other")) continue;
      assert.equal(seen.get(g), undefined, `group ${g} is used by ${seen.get(g)} and ${p.id}`);
      seen.set(g, p.id);
    }
  assert.deepEqual([...seen.keys()].toSorted(), ["atomic", "filter", "proto", "resume"]);
});

test("a once target is not waited for with CURRENT, and the helper waits for every other target", () => {
  const all = NATIVE_PROGRAMS.find((p) => p.id === "native/target-protocol").steps;
  const onceOpen = all.findIndex((s) => s.stream === "once" && s.do === "open");
  assert.equal(all[onceOpen + 1].until.type, "REMOVE");
  const dup = all.findIndex((s) => s.stream === "dup" && s.do === "open");
  assert.deepEqual(all[dup + 1], { do: "wait", stream: "dup", until: { current: 1 }, settleMs: 0 });
  assert.deepEqual(all[dup + 2], { do: "settle" });
});

test("the sweep covers the collection the programs write to", () => {
  assert.deepEqual(SWEEP("ROOT"), [{ parent: "ROOT", collectionId: COLLECTION }]);
  for (const p of NATIVE_PROGRAMS)
    for (const t of Object.values(p.docs)) assert.ok(t.startsWith(`${COLLECTION}/`));
});

test("programProblems reports each fault once, with its step number and kind", () => {
  const open = { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] };
  const close = { do: "close", stream: "s" };
  assert.deepEqual(problemsOf(prog([{ do: "close", stream: "s" }])), [
    "native/p#0 (close): stream s is not open",
  ]);
  assert.deepEqual(
    problemsOf(prog([open, { do: "add", stream: "q", target: { id: 2, doc: "a" } }, close])),
    ["native/p#1 (add): stream q is not open"],
  );
  assert.deepEqual(
    problemsOf(prog([{ do: "open", stream: "s", targets: [{ id: 1, doc: "zz" }] }, close])),
    ["native/p#0 (open): unknown doc zz"],
  );
  assert.deepEqual(
    problemsOf(prog([open, { do: "add", stream: "s", target: { id: 2, doc: "zz" } }, close])),
    ["native/p#1 (add): unknown doc zz"],
  );
  assert.deepEqual(problemsOf(prog([open])), ["native/p: stream s is never closed"]);
  assert.deepEqual(
    problemsOf(prog([{ do: "settle" }, { do: "sleep", ms: 1 }, { do: "mystery" }])),
    ["native/p#2 (mystery): unknown step"],
  );
});

test("every query the programs open filters on its own program's group", () => {
  const groupOf = (id) =>
    ({
      "native/target-protocol": "proto",
      "native/resume-token": "resume",
      "native/existence-filter": "filter",
      "native/commit-atomic-visibility": "atomic",
    })[id];
  let queries = 0;
  for (const p of NATIVE_PROGRAMS)
    for (const step of p.steps)
      for (const t of step.targets ?? []) {
        if (!t.query?.where) continue;
        queries += 1;
        assert.equal(t.query.collection, COLLECTION);
        assert.equal(t.query.where.length, 1);
        const [field, value] = t.query.where[0];
        assert.equal(field, "g");
        assert.ok(
          value === groupOf(p.id) || value === `${groupOf(p.id)}-other`,
          `${p.id}: ${value}`,
        );
      }
  assert.ok(queries >= 10);
});

test("the programs record exactly these rows", () => {
  const rows = NATIVE_PROGRAMS.flatMap((p) =>
    p.steps.filter((s) => s.do === "record").map((s) => s.row),
  );
  assert.deepEqual(rows, [
    "native/target-lifecycle/open",
    "native/target-lifecycle/update",
    "native/target-lifecycle/same-data",
    "native/target-lifecycle/remove",
    "native/target-lifecycle/readd",
    "native/target-lifecycle/delete",
    "native/target-protocol/duplicate-id",
    "native/target-protocol/server-assigned-id",
    "native/target-protocol/id-after-assigned",
    "native/target-protocol/negative-id",
    "native/target-protocol/once",
    "native/target-protocol/read-time-before-write",
    "native/target-protocol/read-time-after-write",
    "native/target-protocol/missing-index",
    "native/target-protocol/equality-only-query",
    "native/target-protocol/collection-group",
    "native/resume-token/first",
    "native/resume-token/current",
    "native/resume-token/older",
    "native/resume-token/unchanged",
    "native/resume-token/invalid",
    "native/resume-token/other-query",
    "native/resume-token/fresh-control",
    "native/existence-filter/first",
    "native/existence-filter/no-change",
    "native/existence-filter/with-expected-count",
    "native/existence-filter/without-expected-count",
    "native/commit-atomic-visibility/open",
    "native/commit-atomic-visibility/transaction",
    "native/commit-atomic-visibility/single-commit",
    "native/commit-atomic-visibility/separate-commits",
  ]);
});
