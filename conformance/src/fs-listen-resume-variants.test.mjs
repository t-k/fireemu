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
    for (const name of [
      "k0",
      "k1",
      "k1-repeat",
      "k1-expected",
      "k2",
      "k2-expected",
      "k2-wrong",
      "k3",
    ])
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
    return steps
      .slice(
        0,
        steps.findIndex((s) => s.do === "save"),
      )
      .map((s) => s.do);
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
  assert.deepEqual(strip("native/resume-grid-tc"), strip("native/resume-grid-g0"));
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
    const from =
      i === 0 ? program.steps.findIndex((s) => s === saves[0]) : program.steps.indexOf(saves[i]);
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
              targetChange: {
                targetChangeType: "NO_CHANGE",
                targetIds: [],
                resumeToken: token("G"),
              },
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
  const grid = (g) =>
    resumes.filter((t) => t.query?.structuredQuery.where.fieldFilter.value.stringValue === g);
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

// ---- the meaning of the programs, against a small model of Firestore --------------------------

/**
 * A model client: documents with fields and a version that each Commit bumps, a snapshot of the
 * documents at each version, and streams whose targets are equality queries on `g`. A target opened
 * with a token resumes from the version the token names; the model records what each open saw:
 * the query, the version it resumed from, the expected count and what changed since.
 */
function modelClient() {
  const docs = new Map();
  const history = [new Map()];
  const opens = [];
  const clock = { t: 0 };
  const live = [];
  const snapshot = () =>
    history.push(new Map([...docs].map(([name, fields]) => [name, { ...fields }])));
  const valueOf = (field) => field.stringValue ?? Number(field.integerValue);
  const plain = (fields) =>
    Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, valueOf(v)]));
  const matches = (version, g) =>
    new Map([...history[version]].filter(([, fields]) => fields.g === g));
  return {
    opens,
    clock,
    version: () => history.length - 1,
    client: {
      async commit({ writes }) {
        for (const write of writes) {
          if (write.delete) docs.delete(write.delete);
          else docs.set(write.update.name, plain(write.update.fields));
        }
        snapshot();
        // A live stream hears of the commit: a document change and a boundary with a later token.
        for (const stream of live)
          stream.frames.push(
            { kind: "documentChange", documentChange: { document: { name: "x" } } },
            {
              kind: "targetChange",
              targetChange: {
                targetChangeType: "NO_CHANGE",
                targetIds: [],
                resumeToken: Buffer.from(`v${history.length - 1}`),
              },
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
          send({ addTarget: target }) {
            const g = target.query.structuredQuery.where.fieldFilter.value.stringValue;
            const now = history.length - 1;
            const from = target.resumeToken ? Number(target.resumeToken.toString().slice(1)) : null;
            const before = from === null ? new Map() : matches(from, g);
            const after = matches(now, g);
            const changed = [...after].filter(
              ([name, f]) =>
                before.has(name) && JSON.stringify(before.get(name)) !== JSON.stringify(f),
            );
            opens.push({
              targetId: target.targetId,
              g,
              from,
              now,
              expectedCount: target.expectedCount?.value ?? null,
              heldAtToken: before.size,
              matchesNow: after.size,
              modified: changed.length,
              entered: [...after.keys()].filter((n) => from !== null && !before.has(n)).length,
              left: [...before.keys()].filter((n) => !after.has(n)).length,
              targets: 1,
            });
            const token = Buffer.from(`v${now}`);
            const change = (type, ids, extra = {}) => ({
              kind: "targetChange",
              targetChange: { targetChangeType: type, targetIds: ids, ...extra },
            });
            frames.push(
              change("ADD", [target.targetId]),
              change("NO_CHANGE", [], { resumeToken: token }),
              change("CURRENT", [target.targetId], { resumeToken: token }),
              change("NO_CHANGE", [], { resumeToken: token }),
            );
          },
          async close() {
            end ??= { reason: "closed-by-harness" };
            live.splice(live.indexOf(stream), 1);
          },
        };
        live.push(stream);
        return stream;
      },
      async missing(names) {
        return names.map((name) => ({ name, exists: docs.has(name) }));
      },
      async listIds() {
        return [];
      },
    },
  };
}

test("each variant resumes what its name says: the commits since the token, the kinds of change, the expected counts and the ages", async () => {
  const model = modelClient();
  const out = await runNative(RESUME_VARIANT_PROGRAMS, {
    client: model.client,
    project: "p1",
    run: "r1",
    sleep: async (ms) => {
      await Promise.resolve();
      model.clock.t += ms;
    },
    now: () => model.clock.t,
    maxRequests: RESUME_VARIANT_REQUEST_CEILING,
  });
  assert.deepEqual(out.errors, {});
  // Every wait of every row held: no row is a wait that ran out.
  assert.deepEqual(
    Object.entries(out.rows)
      .filter(([, row]) => row.timedOut)
      .map(([id]) => id),
    [],
  );
  // The i-th stream opened is the i-th open step of the programs, in run order.
  const openSteps = RESUME_VARIANT_PROGRAMS.flatMap((program) =>
    program.steps
      .map((step, index) => ({ program, step, index }))
      .filter(({ step }) => step.do === "open"),
  );
  assert.equal(model.opens.length, openSteps.length);
  const byStream = new Map(
    openSteps.map(({ program, step }, i) => [`${program.id}:${step.stream}`, model.opens[i]]),
  );
  const seen = (program, stream) => byStream.get(`${program}:${stream}`);
  // Every target is the one target of its stream, with id 1.
  for (const open of model.opens) {
    assert.equal(open.targetId, 1);
    assert.equal(open.targets, 1);
  }
  const shape = (open) => [open.modified, open.entered, open.left];
  for (const [name, tag] of [
    ["g0", "g0"],
    ["tc", "tc"],
    ["gc", "gc"],
  ]) {
    const id = `native/resume-grid-${name}`;
    const rows = {
      first: ["first", [0, 0, 0]],
      k0: ["k0", [0, 0, 0]],
      k1: ["k1", [1, 0, 0]],
      "k1-repeat": ["k1r", [1, 0, 0]],
      "k1-expected": ["k1e", [1, 0, 0]],
      k2: ["k2", [2, 0, 0]],
      "k2-expected": ["k2e", [2, 0, 0]],
      "k2-wrong": ["k2w", [2, 0, 0]],
      k3: ["k3", [2, 0, 1]],
    };
    for (const [row, [stream, want]] of Object.entries(rows)) {
      const open = seen(id, stream);
      assert.equal(open.g, tag, `${id}/${row}: the group of the query`);
      assert.deepEqual(shape(open), want, `${id}/${row}: modified, entered, left since the token`);
    }
    // The client holds the 3 documents of its query at the token; the right count is that number, the wrong one is not.
    for (const stream of ["k0", "k1", "k1r", "k1e", "k2", "k2e", "k2w", "k3"])
      assert.equal(seen(id, stream).heldAtToken, 3, `${id}/${stream}`);
    assert.deepEqual(
      ["k0", "k1", "k1r", "k1e", "k2", "k2e", "k2w", "k3"].map((s) => seen(id, s).expectedCount),
      [null, null, null, 3, null, 3, 4, null],
      id,
    );
    // The resumes are of one token: the version it names is the same in every resume of the grid.
    const versions = new Set(
      ["k0", "k1", "k1r", "k1e", "k2", "k2e", "k2w", "k3"].map((s) => seen(id, s).from),
    );
    assert.equal(versions.size, 1, id);
    // The initial snapshot is a fresh listen (no token) of the 3 documents.
    assert.equal(seen(id, "first").from, null);
    assert.equal(seen(id, "first").matchesNow, 3);
  }
  // Commits since the token, by version: 0, 1, 1, 1, 2, 2, 2, 3 in every grid (the "after a change" grid's token is of its own, later, version).
  for (const name of ["g0", "tc", "gc"])
    assert.deepEqual(
      ["k0", "k1", "k1r", "k1e", "k2", "k2e", "k2w", "k3"].map((s) => {
        const open = seen(`native/resume-grid-${name}`, s);
        return open.now - open.from;
      }),
      [0, 1, 1, 1, 2, 2, 2, 3],
      name,
    );
  // Every listen of a program is of its own group, the first of them an initial snapshot of the 3 documents.
  for (const [program, stream, g] of [
    ["native/resume-kinds", "first", "kinds"],
    ["native/resume-age", "f1", "age"],
    ["native/resume-age", "f2", "age"],
    ["native/resume-age", "f3", "age"],
  ]) {
    assert.equal(seen(program, stream).g, g, `${program}:${stream}`);
    assert.equal(seen(program, stream).from, null, `${program}:${stream}`);
    assert.equal(seen(program, stream).matchesNow, 3, `${program}:${stream}`);
  }
  // Each kind of change, one at a time from the token of the stream before.
  const kinds = (stream) => seen("native/resume-kinds", stream);
  assert.deepEqual(shape(kinds("modify")), [1, 0, 0]);
  assert.deepEqual(shape(kinds("enter")), [0, 1, 0]);
  assert.deepEqual(shape(kinds("leave")), [0, 0, 1]);
  assert.deepEqual(shape(kinds("delete")), [0, 0, 1]);
  for (const stream of ["modify", "enter", "leave", "delete"]) {
    assert.equal(kinds(stream).g, "kinds");
    assert.equal(kinds(stream).expectedCount, null);
    assert.equal(
      kinds(stream).now - kinds(stream).from,
      1,
      `${stream}: one commit since its token`,
    );
  }
  assert.deepEqual(
    ["modify", "enter", "leave", "delete"].map((s) => kinds(s).heldAtToken),
    [3, 3, 4, 3],
  );
  // The three ages.
  const age = (stream) => seen("native/resume-age", stream);
  assert.deepEqual(shape(age("ra")), [1, 0, 0]);
  assert.deepEqual(shape(age("rb")), [1, 0, 0]);
  assert.deepEqual(shape(age("rc")), [2, 0, 0]);
  for (const stream of ["ra", "rb", "rc"]) {
    assert.equal(age(stream).g, "age");
    assert.equal(age(stream).heldAtToken, 3);
    assert.equal(age(stream).expectedCount, null);
  }
  assert.deepEqual(
    ["ra", "rb", "rc"].map((s) => age(s).now - age(s).from),
    [1, 1, 2],
  );
  assert.equal(
    new Set(["ra", "rb", "rc"].map((s) => age(s).from)).size,
    1,
    "the three tokens were taken together",
  );
  // The ages: tokens were taken at t = 0 of the sleeps, 30 s and 300 s before the resumes.
  assert.ok(model.clock.t >= 300_000);
});

test("the streams of each program are named as the design names them", () => {
  const names = (id) =>
    byId(id)
      .steps.filter((s) => s.do === "open")
      .map((s) => s.stream);
  for (const id of GRIDS)
    assert.deepEqual(names(id), ["first", "k0", "k1", "k1r", "k1e", "k2", "k2e", "k2w", "k3"], id);
  assert.deepEqual(names("native/resume-kinds"), ["first", "modify", "enter", "leave", "delete"]);
  assert.deepEqual(names("native/resume-age"), ["f1", "f2", "f3", "ra", "rb", "rc"]);
  // The age waits.
  assert.deepEqual(
    byId("native/resume-age")
      .steps.filter((s) => s.do === "sleep")
      .map((s) => s.ms),
    [30_000, 270_000],
  );
});

test("each program's documents are named with its own tag, so a leftover is found by the run id and the program", () => {
  const tags = {
    "native/resume-grid-g0": "g0",
    "native/resume-grid-tc": "tc",
    "native/resume-grid-gc": "gc",
    "native/resume-kinds": "kinds",
    "native/resume-age": "age",
  };
  for (const [id, tag] of Object.entries(tags))
    assert.deepEqual(
      byId(id).docs,
      Object.fromEntries(["a", "b", "c", "d"].map((d) => [d, `lsn_native/{run}-${tag}-${d}`])),
      id,
    );
});
