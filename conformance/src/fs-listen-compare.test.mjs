import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  canonicalRow,
  classifyRow,
  compareRecordings,
  recordingProblems,
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
    recordingProblems(recording({}, { errors: { "native/x": "boom" } })).join(),
    /native\/x: boom/,
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
