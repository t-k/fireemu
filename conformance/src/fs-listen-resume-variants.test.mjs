import assert from "node:assert/strict";
import { test } from "node:test";

import { NATIVE_PROGRAMS, programProblems } from "./fs-listen/native-programs.mjs";
import { runNative } from "./fs-listen/native-run.mjs";
import {
  RESUME_VARIANT_PROGRAMS,
  RESUME_VARIANT_REQUEST_CEILING,
} from "./fs-listen/native-resume-variants.mjs";

const byId = (id) => RESUME_VARIANT_PROGRAMS.find((program) => program.id === id);
const GRIDS = ["g0", "tc", "gc"].map((name) => `native/resume-grid-${name}`);

test("the resume-variant programs are well formed and apart from the L1 programs", () => {
  assert.deepEqual(programProblems(RESUME_VARIANT_PROGRAMS), []);
  const ids = RESUME_VARIANT_PROGRAMS.map((program) => program.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ids) assert.ok(!NATIVE_PROGRAMS.some((p) => p.id === id), id);
  // Their documents never share a name with another program of the run.
  const names = [...NATIVE_PROGRAMS, ...RESUME_VARIANT_PROGRAMS].flatMap((p) =>
    Object.values(p.docs),
  );
  assert.equal(new Set(names).size, names.length);
  for (const program of RESUME_VARIANT_PROGRAMS) {
    assert.ok(program.conditions.includes("FS-LISTEN-SDK/raw-resume-token"));
    assert.notEqual(program.long, true);
  }
});

const rowsOf = (program) =>
  program.steps.filter((step) => step.do === "record").map((step) => step.row);

test("the programs record exactly the variants of the design note", () => {
  assert.deepEqual(
    RESUME_VARIANT_PROGRAMS.map((p) => p.id),
    [...GRIDS, "native/resume-kinds", "native/resume-age"],
  );
  for (const id of GRIDS)
    assert.deepEqual(
      rowsOf(byId(id)).map((row) => row.slice(id.length + 1)),
      ["first", "k0", "k1", "k1-repeat", "k1-expected", "k2", "k2-expected", "k2-wrong", "k3"],
      id,
    );
  assert.deepEqual(
    rowsOf(byId("native/resume-kinds")).map((row) => row.split("/").at(-1)),
    ["first", "modify", "enter", "leave", "delete"],
  );
  assert.deepEqual(
    rowsOf(byId("native/resume-age")).map((row) => row.split("/").at(-1)),
    ["first", "age-30s-k1", "age-5m-k1", "age-5m-k2"],
  );
});

/** The target of the open step that is followed by the record of `row`. */
function openBefore(program, row) {
  const at = program.steps.findIndex((s) => s.do === "record" && s.row === row);
  const stream = program.steps[at].stream;
  const open = program.steps.findLast((s, i) => i < at && s.do === "open" && s.stream === stream);
  return { open, target: open.targets[0], index: at };
}

test("each grid resumes one saved token at 0, 1, 1 (again), 1, 2, 2, 2 and 3 commits since, with the expected counts of the design", () => {
  for (const id of GRIDS) {
    const program = byId(id);
    const at = (name) => openBefore(program, `${id}/${name}`);
    // One token, saved once from the first stream, used by every resume.
    const saves = program.steps.filter((s) => s.do === "save");
    assert.equal(saves.length, 1, id);
    const token = saves[0].token;
    for (const name of ["k0", "k1", "k1-repeat", "k1-expected", "k2", "k2-expected", "k2-wrong", "k3"])
      assert.equal(at(name).target.resume, token, `${id}/${name}`);
    // The expected count: absent, or the 3 documents the query holds, or a wrong 4.
    for (const name of ["k0", "k1", "k1-repeat", "k2", "k3"])
      assert.equal(at(name).target.expectedCount, undefined, `${id}/${name}`);
    for (const name of ["k1-expected", "k2-expected"])
      assert.equal(at(name).target.expectedCount, 3, `${id}/${name}`);
    assert.equal(at("k2-wrong").target.expectedCount, 4);
    // Commits since the token (writes and deletes between the save and each resume).
    const since = (name) => {
      const from = program.steps.findIndex((s) => s.do === "save");
      return program.steps
        .slice(from, at(name).index)
        .filter((s) => ["write", "delete", "commit", "seed"].includes(s.do)).length;
    };
    assert.deepEqual(
      ["k0", "k1", "k1-repeat", "k1-expected", "k2", "k2-expected", "k2-wrong", "k3"].map(since),
      [0, 1, 1, 1, 2, 2, 2, 3],
      id,
    );
    // The repeated resume is of the same state: no write between k1, k1-repeat and k1-expected.
    const between = (a, b) =>
      program.steps
        .slice(at(a).index, at(b).index)
        .filter((s) => ["write", "delete", "commit"].includes(s.do)).length;
    assert.equal(between("k1", "k1-repeat"), 0);
    assert.equal(between("k1-repeat", "k1-expected"), 0);
    assert.equal(between("k2", "k2-expected"), 0);
    assert.equal(between("k2-expected", "k2-wrong"), 0);
  }
});

test("the three grids differ only in the token: the CURRENT frame's, the global boundary after the initial snapshot, and the global boundary after a change", () => {
  const save = (id) => byId(id).steps.find((s) => s.do === "save");
  assert.equal(save("native/resume-grid-g0").kind, "global");
  assert.equal(save("native/resume-grid-tc").kind, "current");
  assert.equal(save("native/resume-grid-gc").kind, "global");
  // Only the "after a change" grid writes and waits for the change before it saves.
  const before = (id) => {
    const steps = byId(id).steps;
    return steps.slice(0, steps.findIndex((s) => s.do === "save")).map((s) => s.do);
  };
  assert.ok(!before("native/resume-grid-g0").includes("write"));
  assert.ok(!before("native/resume-grid-tc").includes("write"));
  const gc = before("native/resume-grid-gc");
  assert.ok(gc.includes("write"));
  const steps = byId("native/resume-grid-gc").steps;
  const write = steps.findIndex((s) => s.do === "write");
  assert.deepEqual(steps[write + 1], { do: "wait", stream: "first", until: { docChanges: 1 } });
  // The same ordering otherwise: strip the one extra change and the steps match.
  const strip = (id) =>
    byId(id)
      .steps.filter((s) => !(s.do === "save"))
      .map((s) => s.do);
  assert.equal(strip("native/resume-grid-gc").length, strip("native/resume-grid-g0").length + 2);
  assert.deepEqual(
    strip("native/resume-grid-tc"),
    strip("native/resume-grid-g0"),
  );
});

test("the change-kinds program resumes after exactly one change each: modify, enter, leave and delete, each from the token of the stream before", () => {
  const program = byId("native/resume-kinds");
  const row = (name) => openBefore(program, `native/resume-kinds/${name}`);
  const kinds = ["modify", "enter", "leave", "delete"];
  const saves = program.steps.filter((s) => s.do === "save");
  assert.equal(saves.length, 4);
  assert.ok(saves.every((s) => s.kind === "global"));
  kinds.forEach((kind, i) => {
    assert.equal(row(kind).target.resume, saves[i].token, kind);
    assert.equal(row(kind).target.expectedCount, undefined, kind);
    const from = i === 0 ? program.steps.findIndex((s) => s === saves[0]) : program.steps.indexOf(saves[i]);
    // One change between the save the resume uses and the record of its row.
    const changes = program.steps
      .slice(program.steps.indexOf(saves[i]), row(kind).index)
      .filter((s) => ["write", "delete", "commit"].includes(s.do));
    assert.equal(changes.length, 1, kind);
    assert.ok(from >= 0);
  });
  // Each saves from the stream that answered the row before it.
  assert.equal(saves[1].stream, row("modify").open.stream);
  assert.equal(saves[2].stream, row("enter").open.stream);
  assert.equal(saves[3].stream, row("leave").open.stream);
  // The four changes are of four kinds.
  const writes = program.steps.filter((s) => ["write", "delete"].includes(s.do));
  assert.deepEqual(
    writes.map((s) => [s.do, s.doc, s.fields?.g]),
    [
      ["write", "a", "kinds"],
      ["write", "d", "kinds"],
      ["write", "c", "kinds-out"],
      ["delete", "b", undefined],
    ],
  );
});

test("the age program saves three tokens at once, then resumes them at 30 s (1 change), 5 min (1 change) and 5 min (2 changes)", () => {
  const program = byId("native/resume-age");
  const steps = program.steps;
  const saves = steps.filter((s) => s.do === "save");
  assert.equal(saves.length, 3);
  assert.equal(new Set(saves.map((s) => s.token)).size, 3);
  const lastSave = steps.findLastIndex((s) => s.do === "save");
  const firstChange = steps.findIndex((s, i) => i > lastSave && s.do === "write");
  assert.ok(firstChange > lastSave);
  const at = (name) => openBefore(program, `native/resume-age/${name}`);
  const elapsedBefore = (name) =>
    steps
      .slice(lastSave, at(name).index)
      .filter((s) => s.do === "sleep")
      .reduce((sum, s) => sum + s.ms, 0);
  assert.equal(elapsedBefore("age-30s-k1"), 30_000);
  assert.ok(elapsedBefore("age-5m-k1") >= 300_000);
  assert.ok(elapsedBefore("age-5m-k2") >= 300_000);
  // No sleep before the first change and none after the last resume.
  assert.ok(!steps.slice(lastSave, firstChange).some((s) => s.do === "sleep"));
  assert.equal(at("age-30s-k1").target.resume, saves[0].token);
  assert.equal(at("age-5m-k1").target.resume, saves[1].token);
  assert.equal(at("age-5m-k2").target.resume, saves[2].token);
  const changesBefore = (name) =>
    steps.slice(lastSave, at(name).index).filter((s) => ["write", "delete"].includes(s.do)).length;
  assert.deepEqual(["age-30s-k1", "age-5m-k1", "age-5m-k2"].map(changesBefore), [1, 1, 2]);
  // Every wait of these programs stays far inside the token's life (an hour).
  assert.ok(steps.filter((s) => s.do === "sleep").reduce((sum, s) => sum + s.ms, 0) < 10 * 60_000);
});

/** A client whose streams answer with distinct tokens per frame and which pushes a change on each commit. */
function scriptedClient() {
  const sent = [];
  const open = [];
  let commits = 0;
  let tokenN = 0;
  const token = (label) => Buffer.from(`${label}${(tokenN += 1)}`);
  const clock = { t: 0 };
  return {
    sent,
    clock,
    client: {
      async commit() {
        commits += 1;
        for (const stream of open)
          stream.frames.push(
            { kind: "documentChange", documentChange: { document: { name: "x" } } },
            {
              kind: "targetChange",
              targetChange: { targetChangeType: "NO_CHANGE", targetIds: [], resumeToken: token("G") },
            },
          );
        return {};
      },
      async beginTransaction() {
        return Buffer.from("tx");
      },
      openStream() {
        const frames = [];
        let end;
        const stream = {
          frames,
          ended: () => end,
          send(request) {
            sent.push(request.addTarget);
            const id = request.addTarget.targetId;
            const change = (type, ids, extra = {}) => ({
              kind: "targetChange",
              targetChange: { targetChangeType: type, targetIds: ids, ...extra },
            });
            frames.push(
              change("ADD", [id]),
              change("NO_CHANGE", [], { resumeToken: token("B") }),
              change("CURRENT", [id], { resumeToken: token("C") }),
              change("NO_CHANGE", [], { resumeToken: token("G") }),
            );
          },
          async close() {
            end ??= { reason: "closed-by-harness" };
            open.splice(open.indexOf(stream), 1);
          },
        };
        open.push(stream);
        return stream;
      },
      async missing(names) {
        return names.map((name) => ({ name, exists: false }));
      },
      async listIds() {
        return [];
      },
    },
  };
}

test("run against a scripted client: every resume sends the token of its program's save, and the run costs the request count of the design", async () => {
  const { sent, client, clock } = scriptedClient();
  const out = await runNative(RESUME_VARIANT_PROGRAMS, {
    client,
    project: "p1",
    run: "r1",
    sleep: async (ms) => {
      await Promise.resolve();
      clock.t += ms;
    },
    now: () => clock.t,
    maxRequests: RESUME_VARIANT_REQUEST_CEILING,
  });
  assert.deepEqual(out.errors, {});
  assert.equal(out.requests, 59);
  assert.ok(out.requests <= RESUME_VARIANT_REQUEST_CEILING);
  assert.ok(RESUME_VARIANT_REQUEST_CEILING < 100);
  assert.equal(Object.keys(out.rows).length, 3 * 9 + 5 + 4);
  // The resumes carry tokens: kind "current" tokens start with C, the global ones with G.
  const resumes = sent.filter((target) => target.resumeToken);
  assert.equal(resumes.length, 3 * 8 + 4 + 3);
  const text = (target) => target.resumeToken.toString();
  const grid = (g) => resumes.filter((t) => t.query?.structuredQuery.where.fieldFilter.value.stringValue === g);
  assert.ok(grid("tc").every((t) => text(t).startsWith("C")));
  assert.ok(grid("g0").every((t) => text(t).startsWith("G")));
  assert.ok(grid("gc").every((t) => text(t).startsWith("G")));
  // Within a grid every resume carries the one token.
  for (const g of ["g0", "tc", "gc"]) assert.equal(new Set(grid(g).map(text)).size, 1, g);
  // The "after a change" token is a different one from the initial one (a change came in between).
  assert.notEqual(text(grid("gc")[0]), text(grid("g0")[0]));
  // Nothing was held open: the age sleeps ran (300 s).
  assert.ok(clock.t >= 300_000);
});

test("the resume-variant request count is far under the ceiling a production recording of them is held to", () => {
  assert.equal(RESUME_VARIANT_REQUEST_CEILING, 90);
});
