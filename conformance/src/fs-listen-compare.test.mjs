import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  canonicalRow,
  classifyLocal,
  classifyRow,
  describeRow,
  filterKeys,
  filterSites,
  compareRecordings,
  recordingProblems,
  settlementProblems,
} from "./fs-listen/compare.mjs";

// A small seeded generator, so a failing property replays.
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
const pick = (random, list) => list[Math.floor(random() * list.length)];

function randomFrameRow(random) {
  const kind = pick(random, ["targetChange", "documentChange", "documentDelete", "boundary"]);
  if (kind === "boundary") return { kind, resumeToken: random() < 0.5 };
  if (kind === "targetChange")
    return {
      kind,
      type: pick(random, ["ADD", "CURRENT", "REMOVE", "RESET", "NO_CHANGE"]),
      targetIds: [pick(random, [1, 2, 3])],
      cause: random() < 0.2 ? { code: 9, message: "x" } : null,
      resumeToken: random() < 0.5,
    };
  if (kind === "documentChange")
    return {
      kind,
      doc: pick(random, ["a", "b", "c"]),
      fields: { n: Math.floor(random() * 3) },
      targetIds: [1],
      removedTargetIds: [],
    };
  return { kind, doc: pick(random, ["a", "b", "c"]), removedTargetIds: [1] };
}
function randomRow(random) {
  const rows = Array.from({ length: 1 + Math.floor(random() * 8) }, () => randomFrameRow(random));
  return {
    conditions: ["FS-LISTEN-SDK/x"],
    rows,
    end: random() < 0.2 ? { reason: "error", code: 3 } : null,
    timedOut: false,
  };
}

test("a row equals itself, in any seed (reflexive)", () => {
  for (let seed = 1; seed <= 200; seed += 1) {
    const row = randomRow(prng(seed));
    assert.equal(classifyRow(row, structuredClone(row)), "MATCH", `seed ${seed}`);
  }
});

test("the classification is symmetric", () => {
  for (let seed = 1; seed <= 200; seed += 1) {
    const random = prng(seed);
    const a = randomRow(random);
    const b = randomRow(random);
    assert.equal(classifyRow(a, b), classifyRow(b, a), `seed ${seed}`);
  }
});

test("canonicalRow is idempotent", () => {
  for (let seed = 1; seed <= 200; seed += 1) {
    const once = canonicalRow(randomRow(prng(seed)));
    assert.deepEqual(canonicalRow(once), once, `seed ${seed}`);
  }
});

test("documents inside one snapshot compare as a set; across a boundary they do not", () => {
  const doc = (name) => ({
    kind: "documentChange",
    doc: name,
    fields: {},
    targetIds: [1],
    removedTargetIds: [],
  });
  const boundary = { kind: "boundary", resumeToken: true };
  const base = { conditions: [], end: null, timedOut: false };
  const ab = { ...base, rows: [doc("a"), doc("b"), boundary] };
  const ba = { ...base, rows: [doc("b"), doc("a"), boundary] };
  assert.equal(classifyRow(ab, ba), "MATCH");
  const split1 = { ...base, rows: [doc("a"), boundary, doc("b"), boundary] };
  const split2 = { ...base, rows: [doc("b"), boundary, doc("a"), boundary] };
  assert.equal(classifyRow(split1, split2), "DIFFER");
});

test("any single change to a row differs", () => {
  for (let seed = 1; seed <= 200; seed += 1) {
    const random = prng(seed);
    const row = randomRow(random);
    const changed = structuredClone(row);
    const i = Math.floor(random() * changed.rows.length);
    const target = changed.rows[i];
    if (target.kind === "boundary") target.resumeToken = !target.resumeToken;
    else if (target.kind === "targetChange") target.targetIds = [target.targetIds[0] + 10];
    else if (target.kind === "documentChange") target.fields = { n: target.fields.n + 10 };
    else target.doc = `${target.doc}x`;
    assert.equal(classifyRow(row, changed), "DIFFER", `seed ${seed}`);
  }
});

test("the end of a stream and the group structure are part of the row", () => {
  const base = { conditions: [], rows: [], end: null, timedOut: false };
  assert.equal(classifyRow(base, { ...base, end: { reason: "error", code: 3 } }), "DIFFER");
  assert.equal(
    classifyRow(
      { ...base, groups: [{ docs: ["a", "b"], sameUpdateTime: true }] },
      {
        ...base,
        groups: [
          { docs: ["a"], sameUpdateTime: true },
          { docs: ["b"], sameUpdateTime: true },
        ],
      },
    ),
    "DIFFER",
  );
  assert.equal(
    classifyRow(
      { ...base, groups: [{ docs: ["a", "b"], sameUpdateTime: true }] },
      { ...base, groups: [{ docs: ["b", "a"], sameUpdateTime: true }] },
    ),
    "MATCH",
  );
});

test("a row that timed out is INDETERMINATE, never a match or a difference", () => {
  const row = { conditions: [], rows: [], end: null, timedOut: false };
  assert.equal(classifyRow({ ...row, timedOut: true }, row), "INDETERMINATE");
  assert.equal(classifyRow(row, { ...row, timedOut: true }), "INDETERMINATE");
  assert.equal(
    classifyRow({ ...row, timedOut: true }, { ...row, timedOut: true }),
    "INDETERMINATE",
  );
  assert.equal(classifyRow({ ...row, end: { reason: "frame-cap" } }, row), "INDETERMINATE");
});

const recording = (rows, extra = {}) => ({
  version: 1,
  kind: "native",
  errors: {},
  cleanup: { complete: true },
  rows,
  ...extra,
});
const row = (n) => ({
  conditions: ["FS-LISTEN-SDK/x"],
  rows: [{ kind: "boundary", resumeToken: n > 0 }],
  end: null,
  timedOut: false,
});

test("compareRecordings: two matching productions and a matching local are MATCH", () => {
  const out = compareRecordings({
    productions: [recording({ r: row(1) }), recording({ r: row(1) })],
    local: recording({ r: row(1) }),
  });
  assert.equal(out.rows.r.status, "MATCH");
  assert.deepEqual(out.summary, { MATCH: 1 });
  assert.equal(out.ok, true);
});

test("compareRecordings: productions that disagree make the row NONDETERMINISTIC, whatever local says", () => {
  const out = compareRecordings({
    productions: [recording({ r: row(1) }), recording({ r: row(0) })],
    local: recording({ r: row(1) }),
  });
  assert.equal(out.rows.r.status, "NONDETERMINISTIC");
  assert.equal(out.ok, false);
});

test("compareRecordings: local differs from agreeing productions is MISMATCH; a row missing locally is MISSING", () => {
  const out = compareRecordings({
    productions: [recording({ r: row(1), s: row(1) }), recording({ r: row(1), s: row(1) })],
    local: recording({ r: row(0) }),
  });
  assert.equal(out.rows.r.status, "MISMATCH");
  assert.equal(out.rows.s.status, "MISSING");
  assert.equal(out.ok, false);
  assert.deepEqual(out.summary, { MISMATCH: 1, MISSING: 1 });
});

test("compareRecordings: a row only in local is EXTRA, a divergence listed with a reason is KNOWN_DIVERGENCE", () => {
  const out = compareRecordings({
    productions: [recording({ r: row(1) }), recording({ r: row(1) })],
    local: recording({ r: row(0), x: row(1) }),
    divergences: { r: "owner decision D1: reason" },
  });
  assert.equal(out.rows.r.status, "KNOWN_DIVERGENCE");
  assert.equal(out.rows.r.reason, "owner decision D1: reason");
  assert.equal(out.rows.x.status, "EXTRA");
  assert.equal(out.ok, false);
});

test("a divergence never hides a row that matches, and needs a reason", () => {
  const out = compareRecordings({
    productions: [recording({ r: row(1) }), recording({ r: row(1) })],
    local: recording({ r: row(1) }),
    divergences: { r: "stale entry" },
  });
  assert.equal(out.rows.r.status, "MATCH");
  assert.throws(
    () =>
      compareRecordings({
        productions: [recording({ r: row(1) }), recording({ r: row(1) })],
        local: recording({ r: row(0) }),
        divergences: { r: "" },
      }),
    /reason/,
  );
});

test("recordingProblems names an incomplete cleanup, a program error and a wrong kind", () => {
  assert.deepEqual(recordingProblems(recording({})), []);
  assert.match(
    recordingProblems(recording({}, { cleanup: { complete: false } })).join(),
    /cleanup was not complete/,
  );
  assert.match(
    recordingProblems(recording({}, { errors: { "sdk/run": "boom" } })).join(),
    /sdk\/run: boom/,
  );
  assert.match(recordingProblems(recording({}, { version: 2 })).join(), /version/);
});

test("compareRecordings refuses a production recording that is not clean", () => {
  const dirty = recording({ r: row(1) }, { cleanup: { complete: false } });
  assert.throws(
    () =>
      compareRecordings({
        productions: [dirty, recording({ r: row(1) })],
        local: recording({ r: row(1) }),
      }),
    /cleanup was not complete/,
  );
});

test("compareRecordings needs exactly two production recordings", () => {
  assert.throws(
    () => compareRecordings({ productions: [recording({})], local: recording({}) }),
    /two production recordings/,
  );
});

const plain = { conditions: [], end: null, timedOut: false };

test("canonicalRow keeps what a row says and drops the conditions", () => {
  assert.deepEqual(canonicalRow({ ...plain, rows: [] }), { rows: [], end: null });
  assert.deepEqual(
    canonicalRow({ ...plain, observed: [1], failures: ["f"], invariantViolations: [2] }),
    {
      observed: [1],
      failures: ["f"],
      invariantViolations: [2],
      end: null,
    },
  );
  assert.deepEqual(
    canonicalRow({ ...plain, end: { reason: "error", code: 3, details: "x", at: 9 } }).end,
    {
      reason: "error",
      code: 3,
    },
  );
  assert.deepEqual(canonicalRow({ ...plain, end: { reason: "ended" } }).end, {
    reason: "ended",
    code: null,
  });
  assert.deepEqual(
    canonicalRow({ ...plain, groups: [{ docs: ["b", "a"], sameUpdateTime: false }] }).groups,
    [{ docs: ["a", "b"], sameUpdateTime: false }],
  );
  assert.equal("rows" in canonicalRow({ ...plain, observed: [] }), false);
  assert.equal("groups" in canonicalRow({ ...plain, rows: [] }), false);
});

test("each part of a row is compared: observed, failures, violations and the end code", () => {
  const base = { ...plain, observed: [{ a: 1 }], failures: [], invariantViolations: [] };
  assert.equal(classifyRow(base, structuredClone(base)), "MATCH");
  assert.equal(classifyRow(base, { ...base, observed: [{ a: 2 }] }), "DIFFER");
  assert.equal(classifyRow(base, { ...base, failures: ["x"] }), "DIFFER");
  assert.equal(classifyRow(base, { ...base, invariantViolations: [{ invariant: "x" }] }), "DIFFER");
  assert.equal(
    classifyRow(
      { ...base, end: { reason: "error", code: 3 } },
      { ...base, end: { reason: "error", code: 4 } },
    ),
    "DIFFER",
  );
  assert.equal(
    classifyRow(
      { ...base, end: { reason: "error", code: 3 } },
      { ...base, end: { reason: "ended", code: 3 } },
    ),
    "DIFFER",
  );
  // An absent code and a null code are the same.
  assert.equal(
    classifyRow(
      { ...base, end: { reason: "ended" } },
      { ...base, end: { reason: "ended", code: null } },
    ),
    "MATCH",
  );
  assert.equal(
    classifyRow({ ...base, end: null }, { ...base, end: { reason: "ended" } }),
    "DIFFER",
  );
});

test("documents compare as a set only inside one run between non-document rows", () => {
  const d = (doc, kind = "documentChange") => ({ kind, doc, removedTargetIds: [] });
  const t = {
    kind: "targetChange",
    type: "CURRENT",
    targetIds: [1],
    cause: null,
    resumeToken: true,
  };
  const withRows = (rows) => ({ ...plain, rows });
  assert.equal(
    classifyRow(
      withRows([d("a"), d("b", "documentDelete"), t]),
      withRows([d("b", "documentDelete"), d("a"), t]),
    ),
    "MATCH",
  );
  assert.equal(classifyRow(withRows([d("a"), t, d("b")]), withRows([d("b"), t, d("a")])), "DIFFER");
  assert.equal(classifyRow(withRows([t, d("a")]), withRows([d("a"), t])), "DIFFER");
  // Permuting three documents never changes the row.
  const trio = [d("a"), d("b"), d("c")];
  for (const order of [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ])
    assert.equal(
      classifyRow(withRows([...trio, t]), withRows([...order.map((i) => trio[i]), t])),
      "MATCH",
    );
  assert.equal(classifyRow(withRows([d("a"), d("a")]), withRows([d("a")])), "DIFFER");
});

test("an unfinished stream is INDETERMINATE on either side, and a finished one is not", () => {
  const done = { ...plain, rows: [] };
  assert.equal(classifyRow({ ...done, end: { reason: "frame-cap" } }, done), "INDETERMINATE");
  assert.equal(classifyRow(done, { ...done, end: { reason: "frame-cap" } }), "INDETERMINATE");
  assert.equal(
    classifyRow({ ...done, end: { reason: "ended" } }, { ...done, end: { reason: "ended" } }),
    "MATCH",
  );
  assert.equal(
    classifyRow({ ...done, timedOut: false }, { ...done, timedOut: undefined }),
    "MATCH",
  );
});

test("recordingProblems says what is wrong, in order, and nothing when the recording is clean", () => {
  const clean = recording({});
  assert.deepEqual(recordingProblems(clean), []);
  assert.deepEqual(recordingProblems({ ...clean, version: 7 }), ["unknown recording version 7"]);
  assert.deepEqual(recordingProblems({ ...clean, cleanup: undefined }), [
    "cleanup was not complete",
  ]);
  assert.deepEqual(recordingProblems({ ...clean, cleanup: { complete: "yes" } }), [
    "cleanup was not complete",
  ]);
  assert.deepEqual(recordingProblems({ ...clean, errors: undefined }), []);
  assert.deepEqual(
    recordingProblems({ version: 2, cleanup: { complete: false }, errors: { a: "x", b: "y" } }),
    ["unknown recording version 2", "cleanup was not complete", "a: x", "b: y"],
  );
});

test("compareRecordings: every status, one row at a time", () => {
  const p = (rows) => recording(rows);
  const timedOut = { ...row(1), timedOut: true };
  const run = ({ prod1 = {}, prod2 = prod1, local = {}, divergences } = {}) =>
    compareRecordings({ productions: [p(prod1), p(prod2)], local: p(local), divergences });
  assert.equal(run({ prod1: { r: row(1) }, local: { r: row(1) } }).rows.r.status, "MATCH");
  assert.equal(run({ prod1: { r: row(1) }, local: { r: row(0) } }).rows.r.status, "MISMATCH");
  assert.equal(run({ prod1: { r: row(1) } }).rows.r.status, "MISSING");
  assert.equal(
    run({ prod1: { r: row(1) }, prod2: { r: row(0) }, local: { r: row(1) } }).rows.r.status,
    "NONDETERMINISTIC",
  );
  assert.equal(
    run({ prod1: { r: timedOut }, local: { r: row(1) } }).rows.r.status,
    "INDETERMINATE",
  );
  assert.equal(
    run({ prod1: { r: row(1) }, local: { r: timedOut } }).rows.r.status,
    "INDETERMINATE",
  );
  assert.equal(run({ local: { r: row(1) } }).rows.r.status, "EXTRA");
  assert.equal(
    run({ prod1: { r: row(1) }, prod2: {}, local: {} }).rows.r.status,
    "PRODUCTION_MISSING",
  );
  assert.equal(
    run({ prod1: { r: row(1) }, prod2: {}, local: { r: row(1) } }).rows.r.status,
    "EXTRA",
  );
  assert.equal(
    run({ prod1: {}, prod2: { r: row(1) }, local: {} }).rows.r.status,
    "PRODUCTION_MISSING",
  );
  // Rows come out sorted, and the summary counts them.
  const out = run({ prod1: { b: row(1), a: row(1) }, local: { a: row(1), b: row(0) } });
  assert.deepEqual(Object.keys(out.rows), ["a", "b"]);
  assert.deepEqual(out.summary, { MATCH: 1, MISMATCH: 1 });
});

test("compareRecordings: known divergences count as good, an unfit local recording does not", () => {
  const ok = compareRecordings({
    productions: [recording({ r: row(1) }), recording({ r: row(1) })],
    local: recording({ r: row(0) }),
    divergences: { r: "owner decision D1" },
  });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.localProblems, []);
  const dirty = compareRecordings({
    productions: [recording({ r: row(1) }), recording({ r: row(1) })],
    local: recording({ r: row(1) }, { cleanup: { complete: false } }),
  });
  assert.equal(dirty.ok, false);
  assert.deepEqual(dirty.localProblems, ["cleanup was not complete"]);
  for (const reason of ["", "   ", undefined, 7])
    assert.throws(
      () =>
        compareRecordings({
          productions: [recording({}), recording({})],
          local: recording({}),
          divergences: { r: reason },
        }),
      /needs a reason/,
    );
  assert.throws(
    () =>
      compareRecordings({
        productions: [recording({}), recording({}, { errors: { x: "y" } })],
        local: recording({}),
      }),
    /not clean: x: y/,
  );
  assert.throws(
    () => compareRecordings({ productions: [], local: recording({}) }),
    /two production/,
  );
  assert.throws(
    () =>
      compareRecordings({
        productions: [recording({}), recording({}), recording({})],
        local: recording({}),
      }),
    /two production/,
  );
});

test("a documentRemove run compares as a set too, and so do mixed kinds", () => {
  const rm = (doc) => ({ kind: "documentRemove", doc, removedTargetIds: [1] });
  const del = (doc) => ({ kind: "documentDelete", doc, removedTargetIds: [1] });
  const a = { ...plain, rows: [rm("a"), rm("b"), del("c")] };
  const b = { ...plain, rows: [del("c"), rm("b"), rm("a")] };
  assert.equal(classifyRow(a, b), "MATCH");
  assert.equal(classifyRow(a, { ...plain, rows: [rm("a"), rm("b"), rm("c")] }), "DIFFER");
});

test("a production recording that timed out in only one of the two is INDETERMINATE, not a match", () => {
  const timed = { ...row(1), timedOut: true };
  for (const [one, two] of [
    [row(1), timed],
    [timed, row(1)],
  ])
    assert.equal(
      compareRecordings({
        productions: [recording({ r: one }), recording({ r: two })],
        local: recording({ r: row(1) }),
      }).rows.r.status,
      "INDETERMINATE",
    );
});

test("an unclean production recording is refused with every problem, separated by semicolons", () => {
  assert.throws(
    () =>
      compareRecordings({
        productions: [
          recording({}, { cleanup: { complete: false }, errors: { a: "x" } }),
          recording({}),
        ],
        local: recording({}),
      }),
    /a production recording is not clean: cleanup was not complete; a: x$/,
  );
});

const COMPARE = fileURLToPath(new URL("./fs-listen/compare.mjs", import.meta.url));

function runCli(files, args) {
  const dir = mkdtempSync(join(tmpdir(), "fs-listen-cli-"));
  const path = (name, value) => {
    const file = join(dir, name);
    writeFileSync(file, JSON.stringify(value));
    return file;
  };
  const made = Object.fromEntries(
    Object.entries(files).map(([name, value]) => [name, path(name, value)]),
  );
  const out = spawnSync(process.execPath, [COMPARE, ...args(made)], {
    encoding: "utf8",
    env: { ...process.env, NODE_OPTIONS: "" },
  });
  return { code: out.status, stdout: out.stdout, stderr: out.stderr };
}

test("the command line prints one line per row and a summary, and exits 0 only when every row is good", () => {
  const files = {
    p1: recording({ r: row(1), s: row(1) }),
    p2: recording({ r: row(1), s: row(1) }),
    good: recording({ r: row(1), s: row(1) }),
    bad: recording({ r: row(1), s: row(0) }),
    div: { r: "owner decision D9" },
  };
  const ok = runCli(files, (f) => ["--production", f.p1, f.p2, "--local", f.good]);
  assert.equal(ok.code, 0);
  assert.match(ok.stdout, /^MATCH {14}r\nMATCH {14}s\n\{"MATCH":2\} OK\n$/);
  const notOk = runCli(files, (f) => ["--production", f.p1, f.p2, "--local", f.bad]);
  assert.equal(notOk.code, 1);
  assert.match(notOk.stdout, /MISMATCH {11}s\n/);
  assert.match(notOk.stdout, /NOT OK\n$/);
  const known = runCli(files, (f) => [
    "--production",
    f.p1,
    f.p2,
    "--local",
    f.bad,
    "--divergences",
    f.div,
  ]);
  assert.equal(known.code, 1, "the divergence names r, not s");
  const named = runCli({ ...files, div: { s: "owner decision D9" } }, (f) => [
    "--production",
    f.p1,
    f.p2,
    "--local",
    f.bad,
    "--divergences",
    f.div,
  ]);
  assert.equal(named.code, 0);
  assert.match(named.stdout, /KNOWN_DIVERGENCE {3}s {2}\(owner decision D9\)\n/);
});

test("the command line prints the local recording's problems and exits 1", () => {
  const files = {
    p1: recording({ r: row(1) }),
    p2: recording({ r: row(1) }),
    dirty: recording({ r: row(1) }, { cleanup: { complete: false } }),
  };
  const out = runCli(files, (f) => ["--production", f.p1, f.p2, "--local", f.dirty]);
  assert.equal(out.code, 1);
  assert.match(out.stdout, /local: cleanup was not complete\n$/);
});

test("the command line exits 2 with the reason for a bad argument or an unreadable file", () => {
  const stray = runCli({ a: recording({}) }, () => ["--bogus"]);
  assert.equal(stray.code, 2);
  assert.equal(stray.stderr, "unexpected argument --bogus\n");
  assert.equal(stray.stdout, "");
  const missing = runCli({ a: recording({}) }, (f) => [
    "--production",
    f.a,
    f.a,
    "--local",
    "/nonexistent/x.json",
  ]);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /ENOENT/);
  const one = runCli({ a: recording({}) }, (f) => [
    "--production",
    f.a,
    f.a,
    "--local",
    f.a,
    "--production",
    f.a,
    f.a,
  ]);
  assert.equal(one.code, 2);
  assert.match(one.stderr, /two production recordings are required/);
});

test("importing the module does not run the command line", () => {
  const out = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", `import ${JSON.stringify(COMPARE)}; console.log("imported")`],
    {
      encoding: "utf8",
    },
  );
  assert.equal(out.stdout, "imported\n");
  assert.equal(out.status, 0);
});

// Rows production recorded for native Listen streams and SDK listeners (AUTH-FS-CROSS stage 2,
// two recordings): the comparer must read these shapes, and compare the two recordings of one row.
const stage2 = JSON.parse(
  readFileSync(new URL("../auth-fs-cross-stage2-production.json", import.meta.url), "utf8"),
);

test("the comparer reads the recorded production Listen frames: resumed streams from both recordings agree", () => {
  const { resumes, first } = stage2.rows["resume/open"].production;
  const asRow = (frames) => ({ conditions: [], rows: frames, end: null, timedOut: false });
  for (const frames of [first, resumes.same.frames, resumes.switch.frames]) {
    assert.equal(classifyRow(asRow(frames), asRow(structuredClone(frames))), "MATCH");
  }
  // The resume with the same principal and with another one are the same frames.
  assert.equal(classifyRow(asRow(resumes.same.frames), asRow(resumes.switch.frames)), "MATCH");
  // Moving the document change across the CURRENT frame is a difference; the boundary frames stay put.
  const moved = structuredClone(resumes.same.frames);
  const doc = moved.findIndex((f) => f.kind === "documentChange");
  const current = moved.findIndex((f) => f.kind === "targetChange" && f.type === "CURRENT");
  [moved[doc], moved[current]] = [moved[current], moved[doc]];
  assert.equal(classifyRow(asRow(resumes.same.frames), asRow(moved)), "DIFFER");
  // A first stream's frames are not the resumed stream's.
  assert.equal(classifyRow(asRow(first), asRow(resumes.same.frames)), "DIFFER");
});

test("the comparer reads the recorded production listener events, row by row", () => {
  const rows = Object.entries(stage2.rows).filter(([, entry]) => entry.production.listeners);
  assert.ok(rows.length > 30);
  for (const [id, entry] of rows) {
    const observed = entry.production.listeners;
    const a = { conditions: entry.conditions, observed, end: null, timedOut: false };
    assert.equal(classifyRow(a, structuredClone(a)), "MATCH", id);
  }
  const refused = stage2.rows["n-out/listen-signed-out"].production.listeners;
  const permitted = structuredClone(refused);
  permitted["n-out/own-signed-out"] = ["docs:1"];
  assert.equal(
    classifyRow({ ...plain, observed: refused }, { ...plain, observed: permitted }),
    "DIFFER",
  );
});

// A production recording whose program threw: only that program's rows are unfinished (S1).
const prow = (program, n = 1) => ({ ...row(n), program });

test("one program's error makes only that program's rows INDETERMINATE", () => {
  const a = recording(
    { "t/one": prow("native/t1"), "t/two": prow("native/t2") },
    { errors: { "native/t2": "no saved token t0" } },
  );
  const b = recording({ "t/one": prow("native/t1"), "t/two": prow("native/t2") });
  const local = recording({ "t/one": prow("native/t1"), "t/two": prow("native/t2") });
  const report = compareRecordings({ productions: [a, b], local });
  assert.equal(report.rows["t/one"].status, "MATCH");
  assert.equal(report.rows["t/two"].status, "INDETERMINATE");
  assert.equal(report.ok, false, "an unfinished row is never a pass");
  // The same for the local recording, and in the other production recording.
  const badLocal = { ...local, errors: { "native/t2": "boom" } };
  const r2 = compareRecordings({ productions: [b, b], local: badLocal });
  assert.equal(r2.rows["t/two"].status, "INDETERMINATE");
  assert.equal(r2.rows["t/one"].status, "MATCH");
});

test("an error that is not one program's still makes a production recording unfit", () => {
  for (const key of ["sdk/run", "sdk/driver", "native", ""]) {
    const bad = recording({}, { errors: { [key]: "boom" } });
    assert.throws(
      () => compareRecordings({ productions: [bad, recording({})], local: recording({}) }),
      /not clean/,
      key,
    );
  }
});

test("an end with no status is unfinished, like a frame cap", () => {
  const noStatus = { ...row(1), end: { reason: "ended-without-status", code: null } };
  assert.equal(classifyRow(noStatus, row(1)), "INDETERMINATE");
  assert.equal(classifyRow(row(1), noStatus), "INDETERMINATE");
  const ended = { ...row(1), end: { reason: "ended", code: 0 } };
  assert.equal(classifyRow(ended, ended), "MATCH");
});

const RUN_END = "2026-10-05T10:00:00.000Z";
const settledRecording = (extra = {}) =>
  recording(
    { r: row(1) },
    {
      run: "r1",
      endedAt: RUN_END,
      issued: ["n/a", "n/b"],
      cleanup: { complete: false, accounts: { rows: [{ email: "a@example.com", uid: "u1" }] } },
      ...extra,
    },
  );
const readback = (extra = {}) => ({
  run: "r1",
  readAt: "2026-10-05T10:10:00.000Z",
  clean: true,
  names: [
    { name: "n/a", exists: false },
    { name: "n/b", exists: false },
  ],
  accounts: [{ email: "a@example.com", foundByEmail: [], foundByUid: [] }],
  ...extra,
});

test("an incomplete cleanup is accepted with an A2 read-back that names the run and shows everything absent", () => {
  assert.deepEqual(settlementProblems(settledRecording(), readback()), []);
  const ok = compareRecordings({
    productions: [settledRecording(), recording({ r: row(1) })],
    local: recording({ r: row(1) }),
    settlements: [readback()],
  });
  assert.equal(ok.rows.r.status, "MATCH");
  assert.equal(ok.ok, true);
  assert.throws(
    () =>
      compareRecordings({
        productions: [settledRecording(), recording({ r: row(1) })],
        local: recording({ r: row(1) }),
      }),
    /cleanup was not complete$/,
  );
});

test("an A2 read-back that is for another run, too early, not clean or incomplete does not settle", () => {
  const problems = (settlement, recordingExtra) =>
    settlementProblems(settledRecording(recordingExtra), settlement).join(";");
  assert.match(problems(readback({ run: "r2" })), /another run/);
  assert.match(problems(readback({ clean: false })), /not clean/);
  assert.match(problems(readback({ readAt: "2026-10-05T10:09:59.999Z" })), /10 minutes/);
  assert.match(problems(readback({ readAt: "2026-10-05T10:10:00.000Z" })), /^$/);
  assert.match(problems(readback({ readAt: "soon" })), /10 minutes/);
  assert.match(problems(readback({ names: [{ name: "n/a", exists: false }] })), /n\/b absent/);
  assert.match(
    problems(
      readback({
        names: [
          { name: "n/a", exists: false },
          { name: "n/b", exists: true },
        ],
      }),
    ),
    /n\/b absent/,
  );
  assert.match(problems(readback({ accounts: [] })), /account a@example.com absent/);
  assert.match(
    problems(
      readback({ accounts: [{ email: "a@example.com", foundByEmail: ["u1"], foundByUid: [] }] }),
    ),
    /account a@example.com absent/,
  );
  assert.match(
    problems(
      readback({ accounts: [{ email: "a@example.com", foundByEmail: [], foundByUid: null }] }),
    ),
    /account a@example.com absent/,
  );
  assert.match(problems(undefined), /no A2 read-back/);
  assert.match(problems(readback(), { issued: undefined }), /lists no issued names/);
  assert.match(problems(readback(), { run: undefined }), /another run/);
});

test("the command line takes the A2 read-backs with --settlements", () => {
  const files = {
    p1: settledRecording(),
    p2: recording({ r: row(1) }),
    good: recording({ r: row(1) }),
    s: [readback()],
  };
  const withS = runCli(files, (f) => [
    "--production",
    f.p1,
    f.p2,
    "--local",
    f.good,
    "--settlements",
    f.s,
  ]);
  assert.equal(withS.code, 0, withS.stderr);
  const without = runCli(files, (f) => ["--production", f.p1, f.p2, "--local", f.good]);
  assert.equal(without.code, 2);
});

test("a settlement that does not settle keeps the production recording refused, with its reasons", () => {
  assert.throws(
    () =>
      compareRecordings({
        productions: [settledRecording(), recording({ r: row(1) })],
        local: recording({ r: row(1) }),
        settlements: [readback({ clean: false })],
      }),
    /cleanup was not complete; the read-back is not clean/,
  );
});

// ---- optional existence filters, and a wait that ran out because the target was removed ----

const bnd = (resumeToken = true) => ({ kind: "boundary", resumeToken });
const flt = (count, targetId = 1) => ({
  kind: "filter",
  targetId,
  count,
  unchangedNames: { hashCount: 12, bitmapBytes: 4, padding: 7 },
});
const current = {
  kind: "targetChange",
  type: "CURRENT",
  targetIds: [1],
  cause: null,
  resumeToken: true,
};
const fr = (rows, extra = {}) => ({
  conditions: ["x"],
  rows,
  end: null,
  timedOut: false,
  ...extra,
});

test("an existence filter is optional: rows that differ only by one (and the boundary run it splits) match", () => {
  // The recorded pairs of L1 (runs nmuuicyas and nmuukwo6n).
  const withFilter = fr([current, bnd(), flt(2), bnd()]);
  const without = fr([current, bnd()]);
  assert.equal(classifyRow(withFilter, without), "MATCH");
  assert.equal(classifyRow(without, withFilter), "MATCH");
  assert.equal(
    classifyRow(fr([bnd(), flt(3), current, bnd()]), fr([bnd(), current, bnd()])),
    "MATCH",
  );
  assert.equal(classifyRow(fr([current, bnd(), flt(1)]), fr([current, bnd()])), "MATCH");
  assert.deepEqual(canonicalRow(withFilter).rows, [current, bnd()]);
});

test("a filter does not hide another difference, and two filters must agree", () => {
  assert.equal(classifyRow(fr([current, bnd(), flt(2), bnd()]), fr([bnd()])), "DIFFER");
  assert.equal(classifyRow(fr([current, flt(2)]), fr([current, flt(3)])), "DIFFER");
  assert.equal(classifyRow(fr([current, flt(2)]), fr([current, flt(2, 2)])), "DIFFER");
  assert.equal(classifyRow(fr([current, flt(2)]), fr([current, bnd(), flt(2)])), "DIFFER");
  assert.equal(classifyRow(fr([current, flt(2), flt(2)]), fr([current, flt(2)])), "MATCH");
  assert.deepEqual(filterKeys(fr([flt(2), flt(1), flt(2), current])), ["1:1:12:4:7", "1:2:12:4:7"]);
  assert.deepEqual(filterKeys(fr([current])), []);
  assert.deepEqual(filterKeys({}), []);
});

test("dropping a filter merges only the boundaries it left side by side", () => {
  const twoBoundaries = fr([bnd(false), bnd(true)]);
  assert.equal(canonicalRow(twoBoundaries).rows.length, 2, "recorded as two, kept as two");
  assert.deepEqual(canonicalRow(fr([bnd(false), flt(1), bnd(true)])).rows, [bnd(true)]);
  assert.deepEqual(canonicalRow(fr([bnd(true), flt(1), bnd(false)])).rows, [bnd(true)]);
  assert.deepEqual(canonicalRow(fr([bnd(false), flt(1), flt(2), bnd(false)])).rows, [bnd(false)]);
  assert.deepEqual(canonicalRow(fr([flt(1), bnd(true)])).rows, [bnd(true)]);
});

const removed = (code = 3) => ({
  kind: "targetChange",
  type: "REMOVE",
  targetIds: [1],
  cause: { code, message: "bad resume token" },
  resumeToken: false,
});

test("a wait that ran out after the target was removed with a cause is a final answer, not a missing one", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const gone = fr([add, removed()], { timedOut: true });
  assert.equal(classifyRow(gone, structuredClone(gone)), "MATCH");
  assert.equal(classifyRow(gone, fr([add, removed(9)], { timedOut: true })), "DIFFER");
  // Anything else that ran out stays unfinished.
  assert.equal(
    classifyRow(fr([add], { timedOut: true }), fr([add], { timedOut: true })),
    "INDETERMINATE",
  );
  assert.equal(
    classifyRow(fr([removed(), add], { timedOut: true }), fr([removed(), add], { timedOut: true })),
    "INDETERMINATE",
  );
  assert.equal(
    classifyRow(
      fr([add, removed(), current], { timedOut: true }),
      fr([add, removed(), current], { timedOut: true }),
    ),
    "INDETERMINATE",
  );
  const plainRemove = { ...removed(), cause: null };
  assert.equal(
    classifyRow(
      fr([add, plainRemove], { timedOut: true }),
      fr([add, plainRemove], { timedOut: true }),
    ),
    "INDETERMINATE",
  );
  assert.equal(
    classifyRow(fr([], { timedOut: true }), fr([], { timedOut: true })),
    "INDETERMINATE",
  );
  assert.equal(
    classifyRow({ timedOut: true, end: null }, { timedOut: true, end: null }),
    "INDETERMINATE",
  );
});

// ---- the production recordings of L1, replayed ----

const L1 = JSON.parse(
  readFileSync(new URL("../fixtures/fs-listen/l1-production-rows.json", import.meta.url), "utf8"),
).recordings;

test("L1 production, native: the two recordings agree on every row once optional filters are set aside, and each is fit to compare", () => {
  const [a, b] = [L1["native-1"], L1["native-2"]];
  assert.deepEqual(recordingProblems(a), []);
  assert.deepEqual(recordingProblems(b), []);
  const verdicts = Object.keys(a.rows).map((id) => [id, classifyRow(a.rows[id], b.rows[id])]);
  assert.equal(verdicts.length, 35);
  assert.deepEqual(
    verdicts.filter(([, verdict]) => verdict !== "MATCH"),
    [],
  );
});

test("L1 production, native: exactly seven rows carry a filter in one recording and not (or elsewhere) in the other (the evidence for the rule)", () => {
  const [a, b] = [L1["native-1"], L1["native-2"]];
  const shape = (entry) => JSON.stringify(entry.rows.map((item) => item.kind));
  const ids = Object.keys(a.rows).filter((id) => shape(a.rows[id]) !== shape(b.rows[id]));
  assert.deepEqual(ids.toSorted(), [
    "native/existence-filter/no-change",
    "native/resume-token-expired/first",
    "native/resume-token/first",
    "native/resume-token/fresh-control",
    "native/resume-token/other-query",
    "native/resume-token/unchanged",
    "native/target-protocol/equality-only-query",
  ]);
  for (const id of ids) {
    const filters = (entry) => entry.rows.filter((item) => item.kind === "filter").length;
    assert.ok(filters(a.rows[id]) + filters(b.rows[id]) > 0, id);
    const strip = (entry) => entry.rows.filter((item) => item.kind !== "filter").map((i) => i.kind);
    // Apart from filters (and the boundary they split) the frames are the same.
    assert.deepEqual(
      strip(a.rows[id]).filter((k) => k !== "boundary"),
      strip(b.rows[id]).filter((k) => k !== "boundary"),
      id,
    );
  }
});

test("L1 production, SDK: the two recordings agree on all 18 rows", () => {
  const [a, b] = [L1["sdk-1"], L1["sdk-2"]];
  assert.deepEqual(recordingProblems(a), []);
  assert.equal(Object.keys(a.rows).length, 18);
  for (const id of Object.keys(a.rows))
    assert.equal(classifyRow(a.rows[id], b.rows[id]), "MATCH", id);
});

test("only an entry that opts in covers a local wait that ran out for an answer production gave", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const production = fr([add, removed(9)], { timedOut: true });
  const stuck = fr([add], { timedOut: true });
  const recordings = (local) => ({
    productions: [recording({ r: production }), recording({ r: production })],
    local: recording({ r: local }),
  });
  // Without a declaration the row stays unfinished, and a plain declaration (a reason alone, or an
  // entry that does not say `coversLocalTimeout: true`) does not cover it.
  assert.equal(compareRecordings(recordings(stuck)).rows.r.status, "INDETERMINATE");
  for (const entry of [
    "no index needed",
    { reason: "no index needed" },
    { reason: "no index needed", coversLocalTimeout: false },
    { reason: "no index needed", coversLocalTimeout: "yes" },
  ])
    assert.equal(
      compareRecordings({ ...recordings(stuck), divergences: { r: entry } }).rows.r.status,
      "INDETERMINATE",
      JSON.stringify(entry),
    );
  // An entry that opts in makes it a known divergence, and the reason is carried.
  const declared = compareRecordings({
    ...recordings(stuck),
    divergences: { r: { reason: "no index needed", coversLocalTimeout: true } },
  });
  assert.equal(declared.rows.r.status, "KNOWN_DIVERGENCE");
  assert.equal(declared.rows.r.reason, "no index needed");
  // A local wait that ran out on rows equal to production's is slow, not different.
  const slow = compareRecordings({
    ...recordings(production),
    divergences: { r: { reason: "x", coversLocalTimeout: true } },
  });
  assert.equal(slow.rows.r.status, "MATCH");
  // A frame-capped or errored local row is never covered by a divergence.
  const capped = fr([add], { end: { reason: "frame-cap" } });
  assert.equal(
    compareRecordings({
      ...recordings(capped),
      divergences: { r: { reason: "x", coversLocalTimeout: true } },
    }).rows.r.status,
    "INDETERMINATE",
  );
  // An unfinished production row is not covered either.
  const open = fr([add], { timedOut: true });
  assert.equal(
    compareRecordings({
      productions: [recording({ r: open }), recording({ r: open })],
      local: recording({ r: stuck }),
      divergences: { r: { reason: "x", coversLocalTimeout: true } },
    }).rows.r.status,
    "INDETERMINATE",
  );
});

test("the divergence registers name rows of the recorded production run, quote what both runs recorded and cite the runs or the official emulator", () => {
  const read = (name) =>
    JSON.parse(readFileSync(new URL(`../fixtures/fs-listen/${name}`, import.meta.url), "utf8"));
  const strict = read("divergences-strict.json");
  const emulator = read("divergences-emulator.json");
  const rows = new Set(Object.keys(L1["native-1"].rows));
  for (const register of [strict, emulator])
    for (const [id, entry] of Object.entries(register)) {
      assert.ok(rows.has(id), `${id} is not a row of the recorded production run`);
      assert.equal(typeof entry.reason, "string", id);
      assert.ok(entry.reason.length > 80, id);
      assert.match(entry.reason, /nmuuicyas|official emulator/, id);
    }
  // The emulator profile has every strict divergence and the ones the official emulator causes.
  for (const id of Object.keys(strict)) assert.ok(id in emulator, id);
  assert.deepEqual(
    Object.keys(emulator)
      .filter((id) => !(id in strict))
      .toSorted(),
    [
      "native/existence-filter/without-expected-count",
      "native/resume-token-expired/expired",
      "native/resume-token/invalid",
      "native/resume-token/older",
      "native/resume-token/other-query",
      "native/target-protocol/id-after-assigned",
      "native/target-protocol/missing-index",
    ],
  );
  // The four existence-filter rows are declared for the emulator profile only: it keeps the
  // official emulator's behaviour (no ExistenceFilter), cited from the jar; strict reproduces them.
  for (const id of REQUIRED_ROWS) {
    assert.ok(!(id in strict), id);
    assert.match(emulator[id].reason, /cloud-firestore-emulator-v1\.22\.0\.jar/, id);
    assert.match(emulator[id].reason, /nmuuicyas/, id);
    assert.match(emulator[id].reason, /nmuukwo6n/, id);
  }
  for (const id of Object.keys(emulator).filter((i) => !(i in strict)))
    assert.match(emulator[id].reason, /official emulator/, id);
  // The strict ones quote what production recorded (generated from the fixture, not typed): both
  // runs say the same, the entry quotes it, and the entry says it. They cite both runs, name the
  // client effect and the issue, and say what is not measured.
  for (const [id, entry] of Object.entries(strict)) {
    const [first, second] = prodRows(id);
    assert.equal(describeRow(first), describeRow(second), `${id}: the two runs differ`);
    assert.equal(entry.production, describeRow(first), `${id}: the quoted production sequence`);
    assert.ok(entry.reason.includes(entry.production), id);
    assert.match(entry.reason, /consistent across the two runs/, id);
    assert.match(entry.reason, /nmuuicyas/, id);
    assert.match(entry.reason, /nmuukwo6n/, id);
    assert.match(entry.reason, /Native-gRPC client effect/, id);
    assert.match(entry.reason, /SDK effect not measured/, id);
    assert.match(entry.reason, /fs-listen-resume-replay-boundaries/, id);
    assert.equal(typeof entry.fireemu, "string", id);
    assert.notEqual(entry.fireemu, entry.production, id);
    assert.equal(entry.coversLocalTimeout, undefined, id);
    assert.equal(classifyRow(first, second), "MATCH", id);
  }
  // A row whose informative existence filter both production runs sent in the same place is one
  // strict reproduces (it sends the recorded count-only filter), so none of them is declared.
  const informativeOf = (entry) =>
    filterSites(entry)
      .filter((site) => !site.redundant)
      .map((site) => `${site.place}#${site.key}`);
  const required = Object.keys(L1["native-1"].rows).filter((id) => {
    const [first, second] = prodRows(id);
    return informativeOf(first).some((site) => informativeOf(second).includes(site));
  });
  assert.deepEqual(required.toSorted(), REQUIRED_ROWS.toSorted());
  for (const id of required) assert.ok(!(id in strict), `${id} is reproduced, not declared`);
});

test("only the boundaries a dropped filter left side by side merge, however many rows follow it", () => {
  const doc = {
    kind: "documentChange",
    doc: "a",
    fields: {},
    targetIds: [1],
    removedTargetIds: [],
  };
  // A filter early in the row must not make later adjacent boundaries merge.
  assert.deepEqual(canonicalRow(fr([flt(1), doc, bnd(false), bnd(true)])).rows, [
    doc,
    bnd(false),
    bnd(true),
  ]);
  assert.deepEqual(canonicalRow(fr([bnd(true), flt(1), doc, bnd(false), bnd(true)])).rows, [
    bnd(true),
    doc,
    bnd(false),
    bnd(true),
  ]);
});

test("a REMOVE after a CURRENT does not settle a wait that ran out", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const odd = fr([add, current, removed(9)], { timedOut: true });
  assert.equal(classifyRow(odd, structuredClone(odd)), "INDETERMINATE");
});

const bare = (count, extra = {}) => ({
  kind: "filter",
  targetId: 1,
  count,
  unchangedNames: null,
  ...extra,
});

test("near miss: a filter without the bloom filter of unchanged names is not optional and is compared", () => {
  assert.equal(classifyRow(fr([current, bare(2)]), fr([current])), "DIFFER");
  assert.equal(classifyRow(fr([current]), fr([current, bare(2)])), "DIFFER");
  assert.equal(classifyRow(fr([current, bare(2)]), fr([current, bare(2)])), "MATCH");
  assert.equal(classifyRow(fr([current, bare(2)]), fr([current, bare(3)])), "DIFFER");
  // A filter without the field at all is the same.
  const missing = { kind: "filter", targetId: 1, count: 2 };
  assert.equal(classifyRow(fr([current, missing]), fr([current])), "DIFFER");
  // It stays in the canonical row, and does not merge the boundaries around it.
  assert.deepEqual(canonicalRow(fr([bnd(false), bare(1), bnd(true)])).rows, [
    bnd(false),
    bare(1),
    bnd(true),
  ]);
  assert.deepEqual(filterKeys(fr([bare(2), current])), []);
  // A bare filter beside an optional one: the optional one is still optional.
  assert.equal(classifyRow(fr([current, bare(2), flt(2)]), fr([current, bare(2)])), "MATCH");
});

test("near miss: filters that both sides sent must agree on the target, the count and the bloom shape", () => {
  const shaped = (extra) => ({
    ...flt(2),
    unchangedNames: { hashCount: 12, bitmapBytes: 4, padding: 7, ...extra },
  });
  assert.equal(classifyRow(fr([current, shaped({})]), fr([current, shaped({})])), "MATCH");
  for (const change of [{ hashCount: 13 }, { bitmapBytes: 5 }, { padding: 6 }])
    assert.equal(classifyRow(fr([current, shaped({})]), fr([current, shaped(change)])), "DIFFER");
});

test("near miss: a wait that ran out with no REMOVE carrying a cause is a failure, whatever else the row holds", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const noCause = { ...removed(), cause: null };
  for (const rows of [[add], [add, current], [add, noCause], [removed(), add], []]) {
    const waited = fr(rows, { timedOut: true });
    assert.equal(
      classifyRow(waited, structuredClone(waited)),
      "INDETERMINATE",
      JSON.stringify(rows),
    );
  }
  // The same rows, finished, are compared in the ordinary way.
  assert.equal(classifyRow(fr([add, noCause]), fr([add, noCause])), "MATCH");
});

// ---- the review of the L1 comparison (M1, M2, S2): fixture-backed probes ----

const prodRows = (id) => [L1["native-1"].rows[id], L1["native-2"].rows[id]];
/** A local row as fireemu would send it without the filters: the boundaries they split are one. */
const withoutFilterRows = (entry) => {
  const rows = [];
  for (const item of entry.rows) {
    if (item.kind === "filter") continue;
    if (item.kind === "boundary" && rows.at(-1)?.kind === "boundary") continue;
    rows.push(item);
  }
  return { ...entry, rows };
};
const onlyRecording = (rows) => recording(rows);
const verdictOf = (id, local) => {
  const [first, second] = prodRows(id);
  const out = compareRecordings({
    productions: [onlyRecording({ [id]: first }), onlyRecording({ [id]: second })],
    local: onlyRecording({ [id]: local }),
  });
  return out.rows[id].status;
};

test("M1: a local row that leaves out the filter both production runs sent does not match", () => {
  for (const id of [
    "native/existence-filter/without-expected-count",
    "native/resume-token/older",
    "native/resume-token/other-query",
  ]) {
    const [first, second] = prodRows(id);
    assert.ok(
      filterKeys(first).length > 0 && filterKeys(second).length > 0,
      `${id}: both runs sent one`,
    );
    assert.equal(verdictOf(id, withoutFilterRows(first)), "MISMATCH", id);
    assert.equal(verdictOf(id, first), "MATCH", `${id}: the filter itself matches`);
  }
});

test("M1: nothing changed and two documents left the query are different answers", () => {
  const [lost] = prodRows("native/existence-filter/without-expected-count");
  const [unchanged] = prodRows("native/resume-token/unchanged");
  assert.notDeepEqual(filterKeys(lost), filterKeys(unchanged));
  // The local row of 'unchanged' is no answer to 'without-expected-count', and the other way.
  assert.equal(verdictOf("native/existence-filter/without-expected-count", unchanged), "MISMATCH");
});

test("M1: a filter only one production run sent is optional; a local filter neither run sent is a difference", () => {
  const id = "native/resume-token/unchanged";
  const [first, second] = prodRows(id);
  assert.equal(filterKeys(first).length + filterKeys(second).length > 0, true);
  assert.equal(filterKeys(first).length === 0 || filterKeys(second).length === 0, true);
  assert.equal(verdictOf(id, withoutFilterRows(first)), "MATCH", "optional: may be left out");
  assert.equal(verdictOf(id, first), "MATCH");
  assert.equal(verdictOf(id, second), "MATCH");
  const wrong = {
    ...first,
    rows: [
      ...first.rows.slice(0, 2),
      { ...second.rows.find((r) => r.kind === "filter"), count: 0 },
      ...first.rows.slice(2),
    ],
  };
  assert.equal(verdictOf(id, wrong), "MISMATCH", "a count neither run sent");
  const bloom = structuredClone(second);
  bloom.rows.find((r) => r.kind === "filter").unchangedNames.hashCount += 1;
  assert.equal(verdictOf(id, bloom), "MISMATCH", "a bloom shape neither run sent");
});

test("M2: a strict register entry can never cover a local hang or an empty local row", () => {
  const strict = JSON.parse(
    readFileSync(new URL("../fixtures/fs-listen/divergences-strict.json", import.meta.url), "utf8"),
  );
  const emulator = JSON.parse(
    readFileSync(
      new URL("../fixtures/fs-listen/divergences-emulator.json", import.meta.url),
      "utf8",
    ),
  );
  for (const [id, entry] of Object.entries(strict)) {
    assert.equal(typeof entry === "string" || entry.coversLocalTimeout !== true, true, id);
    for (const rows of [
      [],
      [{ kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false }],
    ]) {
      const [first, second] = prodRows(id);
      const out = compareRecordings({
        productions: [onlyRecording({ [id]: first }), onlyRecording({ [id]: second })],
        local: onlyRecording({ [id]: fr(rows, { timedOut: true }) }),
        divergences: { [id]: entry },
      });
      assert.notEqual(out.rows[id].status, "KNOWN_DIVERGENCE", id);
      assert.equal(out.ok, false);
    }
  }
  // Only one emulator entry opts in: the missing index the official emulator serves.
  const optIn = Object.entries(emulator).filter(([, entry]) => entry.coversLocalTimeout === true);
  assert.deepEqual(
    optIn.map(([id]) => id),
    ["native/target-protocol/missing-index"],
  );
});

test("S2: a REMOVE without a cause, with a cause that has no code, or of a target the row never added is not an answer", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const rem = (extra) => ({
    kind: "targetChange",
    type: "REMOVE",
    targetIds: [1],
    resumeToken: false,
    ...extra,
  });
  const unfinished = (rows) => {
    const waited = fr(rows, { timedOut: true });
    return classifyRow(waited, structuredClone(waited)) === "INDETERMINATE";
  };
  assert.equal(unfinished([add, rem({})]), true, "no cause key");
  assert.equal(unfinished([add, rem({ cause: null })]), true);
  assert.equal(unfinished([add, rem({ cause: { message: "x" } })]), true, "no code");
  assert.equal(
    unfinished([add, rem({ cause: { code: "3", message: "x" } })]),
    true,
    "code not a number",
  );
  assert.equal(
    unfinished([add, rem({ targetIds: [2], cause: { code: 3, message: "x" } })]),
    true,
    "never added",
  );
  assert.equal(
    unfinished([add, rem({ targetIds: [], cause: { code: 3, message: "x" } })]),
    true,
    "no target",
  );
  assert.equal(
    unfinished([add, rem({ targetIds: [1, 2], cause: { code: 3, message: "x" } })]),
    true,
    "one never added",
  );
  // The recorded shapes: ADD then REMOVE with a cause, and a REMOVE of a junk token on its own.
  assert.equal(unfinished([add, rem({ cause: { code: 9, message: "x" } })]), false);
  assert.equal(unfinished([rem({ cause: { code: 3, message: "bad resume token" } })]), false);
  // A lone REMOVE is accepted only when it is the row's only target change.
  assert.equal(unfinished([bnd(), rem({ cause: { code: 3, message: "x" } })]), false);
  assert.equal(
    unfinished([{ ...add, type: "NO_CHANGE" }, rem({ cause: { code: 3, message: "x" } })]),
    true,
  );
});

test("classifyLocal: the frames decide; a filter both production runs sent is required, one only a run sent is optional, one neither sent is a difference; unfinished rows are not compared", () => {
  const withFilter = (count) => fr([current, bnd(), flt(count)]);
  const none = fr([current, bnd()]);
  assert.equal(classifyLocal(withFilter(2), withFilter(2), withFilter(2)), "MATCH");
  assert.equal(classifyLocal(withFilter(2), withFilter(2), none), "DIFFER", "required");
  assert.equal(classifyLocal(withFilter(2), none, none), "MATCH", "optional");
  assert.equal(classifyLocal(withFilter(2), none, withFilter(2)), "MATCH");
  assert.equal(classifyLocal(withFilter(2), none, withFilter(3)), "DIFFER", "a count neither sent");
  assert.equal(classifyLocal(none, none, withFilter(2)), "DIFFER");
  assert.equal(
    classifyLocal(withFilter(2), withFilter(3), fr([current, bnd(), flt(2), flt(3)])),
    "MATCH",
  );
  assert.equal(classifyLocal(withFilter(2), withFilter(3), none), "MATCH", "no filter both sent");
  assert.equal(classifyLocal(none, none, fr([bnd()])), "DIFFER", "frames differ");
  const waited = fr([current], { timedOut: true });
  for (const [a, b, c] of [
    [waited, none, none],
    [none, waited, none],
    [none, none, waited],
  ])
    assert.equal(classifyLocal(a, b, c), "INDETERMINATE");
});

test("describeRow quotes every kind of frame, its target ids, cause and token, and the filters of the row", () => {
  const target = (type, extra = {}) => ({
    kind: "targetChange",
    type,
    targetIds: [1],
    cause: null,
    resumeToken: false,
    ...extra,
  });
  const change = (extra = {}) => ({
    kind: "documentChange",
    doc: "a",
    fields: {},
    targetIds: [1],
    removedTargetIds: [],
    ...extra,
  });
  const text = (rows) => describeRow(fr(rows));
  assert.equal(text([]), "");
  assert.equal(text([target("ADD")]), "ADD[1]");
  assert.equal(text([target("ADD", { targetIds: [] })]), "ADD");
  assert.equal(text([target("CURRENT", { resumeToken: true })]), "CURRENT[1]+token");
  assert.equal(text([target("REMOVE", { cause: { code: 9, message: "m" } })]), "REMOVE[1](code 9)");
  assert.equal(text([bnd(true)]), "boundary+token");
  assert.equal(text([bnd(false)]), "boundary");
  assert.equal(text([change()]), "change a");
  assert.equal(
    text([change({ targetIds: [], removedTargetIds: [1] })]),
    "change a (removed target ids)",
  );
  assert.equal(
    text([{ kind: "documentDelete", doc: "b", removedTargetIds: [1] }]),
    "documentDelete b",
  );
  assert.equal(
    text([{ kind: "documentRemove", doc: "b", removedTargetIds: [1] }]),
    "documentRemove b",
  );
  assert.equal(text([{ kind: "mystery" }]), "mystery");
  assert.equal(
    text([target("ADD"), bnd(true), flt(2), flt(1), flt(2), current]),
    "ADD[1], boundary+token, CURRENT[1]+token | filters 1:1:12:4:7 1:2:12:4:7",
  );
  assert.equal(text([flt(3)]), " | filters 1:3:12:4:7");
  // A filter without a bloom filter stays a frame of the row (it is compared there).
  assert.equal(text([current, bare(2)]), "CURRENT[1]+token, filter(1,2)");
  assert.equal(text([bare(2), flt(2)]), "filter(1,2) | filters 1:2:12:4:7");
  assert.equal(describeRow({}), "");
});

test("classifyLocal: a program that threw, a stream that ended with no status and a frame cap are unfinished, whichever side", () => {
  const ok = fr([current]);
  for (const bad of [
    fr([current], { programError: true }),
    fr([current], { end: { reason: "ended-without-status", code: null } }),
    fr([current], { end: { reason: "frame-cap" } }),
  ])
    for (const [a, b, c] of [
      [bad, ok, ok],
      [ok, bad, ok],
      [ok, ok, bad],
    ])
      assert.equal(classifyLocal(a, b, c), "INDETERMINATE");
  assert.equal(
    classifyLocal(ok, ok, fr([current], { end: { reason: "ended", code: 0 } })),
    "DIFFER",
  );
});

test("a production pair that is unfinished stays INDETERMINATE even when no local row exists", () => {
  const waiting = fr([current], { timedOut: true });
  const out = compareRecordings({
    productions: [recording({ r: waiting }), recording({ r: waiting })],
    local: recording({}),
  });
  assert.equal(out.rows.r.status, "INDETERMINATE");
});

// ---- v3: a required filter is matched by place; one that repeats a known count carries nothing ----

const REQUIRED_ROWS = [
  "native/resume-token/older",
  "native/resume-token/other-query",
  "native/existence-filter/without-expected-count",
  "native/resume-token-expired/expired",
];

/** `entry` with its first filter taken out and put back before frame `index` of the rest. */
function movedFilter(entry, index) {
  const at = entry.rows.findIndex((item) => item.kind === "filter");
  const filter = entry.rows[at];
  const rest = entry.rows.filter((_, i) => i !== at);
  return { ...entry, rows: [...rest.slice(0, index), filter, ...rest.slice(index)] };
}

test("M4: the filters both production runs sent are required where they were sent: dropping one, or moving it across CURRENT or after the last boundary, does not match", () => {
  for (const id of REQUIRED_ROWS) {
    const [first, second] = prodRows(id);
    const sites = (entry) => filterSites(entry).filter((site) => !site.redundant);
    assert.ok(sites(first).length > 0 && sites(second).length > 0, `${id}: informative in both`);
    assert.equal(verdictOf(id, first), "MATCH", id);
    assert.equal(verdictOf(id, withoutFilterRows(first)), "MISMATCH", `${id}: dropped`);
    const filterAt = first.rows.findIndex((item) => item.kind === "filter");
    const currentAt = first.rows.findIndex(
      (item) => item.kind === "targetChange" && item.type === "CURRENT",
    );
    // The first filter moved to just after CURRENT, and to the very end.
    const rest = first.rows.length - 1;
    for (const index of [currentAt + 1 - (filterAt < currentAt ? 1 : 0), rest]) {
      const moved = movedFilter(first, index);
      if (JSON.stringify(moved.rows) === JSON.stringify(first.rows)) continue;
      assert.equal(verdictOf(id, moved), "MISMATCH", `${id}: moved to ${index}`);
    }
  }
});

test("M4: older's filter before CURRENT does not match one after the final boundary", () => {
  const [first] = prodRows("native/resume-token/older");
  const atEnd = {
    ...first,
    rows: [
      ...first.rows.filter((item) => item.kind !== "filter"),
      first.rows.find((item) => item.kind === "filter"),
    ],
  };
  assert.equal(verdictOf("native/resume-token/older", atEnd), "MISMATCH");
  assert.deepEqual(
    filterSites(first).map((site) => site.place),
    ["4|targetChange:CURRENT"].map((place) => place),
  );
  assert.notEqual(filterSites(atEnd)[0].place, filterSites(first)[0].place);
});

test("a filter that repeats a count the row already says carries nothing: on a fresh target after CURRENT, or after a filter of the same count", () => {
  for (const id of [
    "native/target-protocol/collection-group",
    "native/resume-token-expired/fresh-control",
  ]) {
    const [first, second] = prodRows(id);
    assert.ok(
      filterSites(first).every((site) => site.redundant),
      `${id}: redundant`,
    );
    assert.equal(verdictOf(id, first), "MATCH", id);
    assert.equal(verdictOf(id, withoutFilterRows(first)), "MATCH", `${id}: may be left out`);
    // Sent with the wrong count it says something the row contradicts: a difference.
    const wrong = structuredClone(first);
    wrong.rows.find((item) => item.kind === "filter").count += 1;
    assert.equal(verdictOf(id, wrong), "MISMATCH", `${id}: a count the row does not hold`);
    assert.ok(second);
  }
  // The second filter of expired/expired repeats the first one's count; other-query's too.
  for (const id of ["native/resume-token-expired/expired", "native/resume-token/other-query"]) {
    const [, second] = prodRows(id);
    const sites = filterSites(second);
    assert.equal(sites.at(-1).redundant, true, `${id}: the last filter is a repeat`);
    assert.equal(sites[0].redundant, false, `${id}: the first one is information`);
  }
});

test("filterSites: places, redundancy by held documents, by an earlier count, and only after CURRENT", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const change = (doc, extra = {}) => ({
    kind: "documentChange",
    doc,
    fields: {},
    targetIds: [1],
    removedTargetIds: [],
    ...extra,
  });
  const del = (doc) => ({ kind: "documentDelete", doc, removedTargetIds: [1] });
  const sites = (rows) => filterSites(fr(rows));
  // A fresh target holding two documents: a filter of 2 after CURRENT is a repeat, of 3 is not.
  const fresh = [add, change("a"), change("b"), current, bnd()];
  assert.deepEqual(
    sites([...fresh, flt(2)]).map((s) => s.redundant),
    [true],
  );
  assert.deepEqual(
    sites([...fresh, flt(3)]).map((s) => s.redundant),
    [false],
  );
  // A document taken back is not held.
  assert.deepEqual(
    sites([add, change("a"), change("b"), del("b"), current, flt(1)]).map((s) => s.redundant),
    [true],
  );
  assert.deepEqual(
    sites([add, change("a"), change("b"), del("b"), current, flt(2)]).map((s) => s.redundant),
    [false],
  );
  assert.deepEqual(
    sites([
      add,
      change("a"),
      change("a", { targetIds: [], removedTargetIds: [1] }),
      current,
      flt(0),
    ]).map((s) => s.redundant),
    [true],
    "a change that took the document out of the target",
  );
  // Before CURRENT a filter is information, fresh or not.
  assert.deepEqual(
    sites([add, change("a"), flt(1), current]).map((s) => s.redundant),
    [false],
  );
  // A resumed target (a boundary right after ADD) holds what the client held: only a repeated count is redundant.
  const resumed = [add, bnd(), change("a"), flt(1), current, bnd()];
  assert.deepEqual(
    sites([...resumed, flt(1)]).map((s) => s.redundant),
    [false, true],
  );
  assert.deepEqual(
    sites([...resumed, flt(2)]).map((s) => s.redundant),
    [false, false],
  );
  // A filter without a bloom filter is not a site.
  assert.deepEqual(sites([add, bare(1), current]), []);
  // Places: the frames before it (filters dropped, boundaries merged) and the frame after it.
  assert.deepEqual(
    sites([add, bnd(), flt(0), flt(0), bnd(), current, bnd(), flt(0), bnd()]).map((s) => s.place),
    ["2|boundary", "2|boundary", "4|boundary"],
  );
  assert.deepEqual(
    sites([add, flt(0)]).map((s) => s.place),
    ["1|end"],
  );
  assert.deepEqual(sites([]), []);
  assert.deepEqual(filterSites({}), []);
});

test("filterSites: a target that was never added is not fresh; a resumed one is not either; a frame that adds or removes nothing keeps its document", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const change = (doc, extra = {}) => ({
    kind: "documentChange",
    doc,
    fields: {},
    targetIds: [1],
    removedTargetIds: [],
    ...extra,
  });
  const redundant = (rows) => filterSites(fr(rows)).map((site) => site.redundant);
  // No ADD in the row: nothing says the target started empty, so a repeated document count is information.
  assert.deepEqual(redundant([change("a"), current, flt(1)]), [false]);
  // A target resumed (a boundary right after its ADD) is not fresh whatever follows.
  assert.deepEqual(redundant([add, bnd(), change("a"), current, flt(1)]), [false]);
  assert.deepEqual(redundant([add, bnd(), change("a"), current, bnd(), flt(1)]), [false]);
  // The same target added fresh: the count repeats what the row delivered.
  assert.deepEqual(redundant([add, change("a"), current, flt(1)]), [true]);
  // A change that names no target either way leaves the document held; a documentRemove takes it out.
  assert.deepEqual(
    redundant([
      add,
      change("a"),
      change("a", { targetIds: [], removedTargetIds: [] }),
      current,
      flt(1),
    ]),
    [true],
  );
  assert.deepEqual(
    redundant([
      add,
      change("a"),
      change("a", { targetIds: [], removedTargetIds: [] }),
      current,
      flt(0),
    ]),
    [false],
  );
  assert.deepEqual(
    redundant([
      add,
      change("a"),
      { kind: "documentRemove", doc: "a", removedTargetIds: [1] },
      current,
      flt(0),
    ]),
    [true],
  );
  assert.deepEqual(
    redundant([
      add,
      change("a"),
      change("b", { targetIds: [], removedTargetIds: [1] }),
      current,
      flt(1),
    ]),
    [true],
    "a document never held that leaves the target",
  );
});

test("filterSites keeps its state per target: another target's count, documents or CURRENT excuse nothing, and a target the row never added is never excused", () => {
  const addT = (...ids) => ({
    kind: "targetChange",
    type: "ADD",
    targetIds: ids,
    cause: null,
    resumeToken: false,
  });
  const currentT = (...ids) => ({ ...current, targetIds: ids });
  const docFor = (doc, ...ids) => ({
    kind: "documentChange",
    doc,
    fields: {},
    targetIds: ids,
    removedTargetIds: [],
  });
  const redundant = (rows) => filterSites(fr(rows)).map((site) => site.redundant);
  // The reviewer's probe: target 1 fresh with 2 documents repeats its count; target 2 was resumed
  // (a boundary right after its ADD) and its filter of the same count is information.
  assert.deepEqual(
    redundant([
      addT(1),
      docFor("a", 1),
      docFor("b", 1),
      currentT(1),
      bnd(),
      flt(2, 1),
      bnd(),
      addT(2),
      bnd(),
      currentT(2),
      bnd(),
      flt(2, 2),
      bnd(),
    ]),
    [true, false],
  );
  // A repeated count of another target is not this target's earlier count.
  assert.deepEqual(redundant([addT(1), addT(2), currentT(1, 2), flt(5, 1), flt(5, 2)]), [
    false,
    false,
  ]);
  assert.deepEqual(
    redundant([addT(1), addT(2), currentT(1, 2), flt(5, 1), flt(5, 1)]),
    [false, true],
    "the same target repeating its own count",
  );
  // Documents delivered to target 2 are not held by target 1.
  assert.deepEqual(redundant([addT(1), addT(2), docFor("a", 2), currentT(1, 2), flt(1, 1)]), [
    false,
  ]);
  assert.deepEqual(redundant([addT(1), addT(2), docFor("a", 2), currentT(1, 2), flt(1, 2)]), [
    true,
  ]);
  // Another target's CURRENT does not make this one's earlier filter redundant.
  assert.deepEqual(redundant([addT(1), docFor("a", 1), addT(2), currentT(2), flt(1, 1)]), [false]);
  // A change that adds to one target and takes the document out of another.
  assert.deepEqual(
    redundant([
      addT(1),
      addT(2),
      docFor("a", 1, 2),
      { ...docFor("a", 2), removedTargetIds: [1] },
      currentT(1, 2),
      flt(0, 1),
      flt(1, 2),
    ]),
    [true, true],
  );
  // A delete names the targets it leaves; one that names none leaves every target.
  const gone = (removedTargetIds) => ({ kind: "documentDelete", doc: "a", removedTargetIds });
  assert.deepEqual(
    redundant([
      addT(1),
      addT(2),
      docFor("a", 1, 2),
      gone([2]),
      currentT(1, 2),
      flt(1, 1),
      flt(0, 2),
    ]),
    [true, true],
  );
  assert.deepEqual(
    redundant([
      addT(1),
      addT(2),
      docFor("a", 1, 2),
      gone([]),
      currentT(1, 2),
      flt(0, 1),
      flt(0, 2),
    ]),
    [true, true],
  );
  assert.deepEqual(
    redundant([addT(1), addT(2), docFor("a", 1, 2), gone([2]), currentT(1, 2), flt(0, 1)]),
    [false],
    "target 1 still holds the document",
  );
  // A filter of a target the row never added is information, whatever it repeats.
  assert.deepEqual(redundant([addT(1), docFor("a", 1), currentT(1), flt(1, 9)]), [false]);
  assert.deepEqual(redundant([flt(1, 9), currentT(9), flt(1, 9)]), [false, false]);
});

test("the committed production rows: a post-CURRENT filter moved to a target the row never added is not excused", () => {
  for (const id of [
    "native/target-protocol/collection-group",
    "native/resume-token-expired/fresh-control",
  ]) {
    const [first, second] = prodRows(id);
    assert.equal(classifyLocal(first, second, first), "MATCH", id);
    const foreign = (row) => ({
      ...row,
      rows: row.rows.map((item) => (item.kind === "filter" ? { ...item, targetId: 9 } : item)),
    });
    assert.equal(classifyLocal(first, second, foreign(first)), "DIFFER", `${id}: a foreign target`);
  }
});

test("filterSites: only the boundaries a dropped filter left side by side merge into one place", () => {
  const places = (rows) => filterSites(fr(rows)).map((site) => site.place);
  // Two boundaries nothing was between stay two frames.
  assert.deepEqual(places([bnd(), bnd(), flt(0), current]), ["2|targetChange:CURRENT"]);
  // A filter between two boundaries: they are one frame.
  assert.deepEqual(places([bnd(), flt(0), bnd(), flt(0)]), ["1|boundary", "1|end"]);
  // A boundary and a document after a dropped filter are two frames.
  assert.deepEqual(places([bnd(), flt(0), current, flt(0)]), ["1|targetChange:CURRENT", "2|end"]);
  // The merge applies once: a boundary after the merged pair counts again.
  assert.deepEqual(places([flt(0), bnd(), bnd(), flt(0)]), ["0|boundary", "2|end"]);
  assert.deepEqual(places([bnd(), flt(0), bnd(), bnd(), flt(0)]), ["1|boundary", "2|end"]);
});

test("a repeated count is not information: two runs with different redundant filters in one place still match", () => {
  const add = {
    kind: "targetChange",
    type: "ADD",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const doc = {
    kind: "documentChange",
    doc: "a",
    fields: {},
    targetIds: [1],
    removedTargetIds: [],
  };
  const other = { ...flt(1), unchangedNames: { hashCount: 13, bitmapBytes: 8, padding: 3 } };
  const base = [add, doc, current, bnd()];
  assert.equal(classifyRow(fr([...base, flt(1)]), fr([...base, other])), "MATCH");
  // The same filters before CURRENT are information and must agree.
  const early = [add, doc];
  assert.equal(
    classifyRow(fr([...early, flt(1), current]), fr([...early, other, current])),
    "DIFFER",
  );
});

test("two rows that both have a filter in the same place must say the same; one only a row has is optional", () => {
  const a = fr([current, flt(2), bnd()]);
  const b = fr([current, flt(3), bnd()]);
  assert.equal(classifyRow(a, b), "DIFFER");
  assert.equal(classifyRow(a, fr([current, bnd()])), "MATCH");
  assert.equal(classifyRow(a, fr([current, bnd(), flt(3)])), "MATCH", "another place");
  assert.equal(classifyRow(a, structuredClone(a)), "MATCH");
});
