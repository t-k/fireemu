import assert from "node:assert/strict";
import { test } from "node:test";

import { NATIVE_PROGRAMS, programProblems } from "./fs-listen/native-programs.mjs";
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
