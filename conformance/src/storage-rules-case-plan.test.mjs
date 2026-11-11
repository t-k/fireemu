import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  CANDIDATES,
  CASE_PLAN,
  CASE_ROWS,
  predictRow,
  ruleSource,
} from "./storage-rules-s9/plan-case.mjs";
import { S9_PLAN, buildPlan } from "./storage-rules-s9/plan.mjs";

const cp = (...points) => String.fromCodePoint(...points);
const DOTTED = cp(0x130);
const runId = "sr-0123abcd";
const P = CASE_PLAN.recordingPrefix(runId, 1);

// An independent reference of the three candidates. JavaScript's own tables are the full Unicode
// default case mapping (sharp s to SS, dotted I to i + U+0307, final sigma by context).
const ascii = (text, fn) =>
  fn === "lower"
    ? text.replace(/[A-Z]/g, (c) => c.toLowerCase())
    : text.replace(/[a-z]/g, (c) => c.toUpperCase());
const full = (text, fn) => (fn === "lower" ? text.toLowerCase() : text.toUpperCase());
const simple = (text, fn) =>
  [...text]
    .map((ch) => {
      const mapped = fn === "lower" ? ch.toLowerCase() : ch.toUpperCase();
      if ([...mapped].length === 1) return mapped;
      return fn === "lower" && ch === DOTTED ? "i" : ch; // simple lowercase of dotted I is i
    })
    .join("");
const MAPS = { ascii, full, simple };

function reference(row, candidate) {
  const map = MAPS[candidate];
  const applied = (text) => (row.fn ? map(text, row.fn) : text);
  if (row.kind === "literal")
    return row.rel === "size"
      ? applied(row.input).length === row.operand
      : applied(row.input) === row.operand;
  if (row.kind === "capture") return applied(row.objectName) === row.operand;
  const name = CASE_PLAN.objectName(row.object, P);
  return row.rel === "same" ? applied(name) === name : applied(name) !== name;
}

describe("the case family plan", () => {
  it("is one released program, no load-only rulesets, its own prefix and task", () => {
    assert.equal(CASE_PLAN.id, "case");
    assert.equal(CASE_PLAN.taskId, "STORAGE-RULES-CASE");
    assert.equal(CASE_PLAN.prefixRoot, "storage-rules-case");
    assert.deepEqual(
      CASE_PLAN.programs.map((p) => p.id),
      ["case"],
    );
    assert.deepEqual(CASE_PLAN.loadOnly, []);
    assert.equal(CASE_PLAN.runRoot(runId), `storage-rules-case/${runId}/`);
    assert.equal(P, `storage-rules-case/${runId}/rec1`);
    assert.deepEqual(CANDIDATES, ["ascii", "full", "simple"]);
  });

  it("has a marker and one object per row, every object under the recording prefix", () => {
    const program = CASE_PLAN.programs[0];
    assert.equal(program.marker, "mkA");
    assert.deepEqual(
      Object.keys(CASE_PLAN.objects).toSorted(),
      [...CASE_ROWS.map((r) => r.object), "mkA"].toSorted(),
    );
    assert.equal(new Set(CASE_ROWS.map((r) => r.id)).size, CASE_ROWS.length);
    assert.equal(new Set(CASE_ROWS.map((r) => r.object)).size, CASE_ROWS.length);
    assert.deepEqual(program.objects.toSorted(), Object.keys(CASE_PLAN.objects).toSorted());
    for (const id of Object.keys(CASE_PLAN.objects)) {
      const name = CASE_PLAN.objectName(id, P);
      assert.ok(name.startsWith(`${P}/`), name);
      assert.ok(![...name].some((c) => c.charCodeAt(0) < 0x20 || c.charCodeAt(0) === 0x7f), name);
      assert.ok(!name.split("/").some((s) => s === "" || s === "." || s === ".."), name);
    }
    assert.equal(CASE_ROWS.length, 39);
  });

  it("reads every row of the table through get on the object (meta op) in the one program", () => {
    for (const row of CASE_PLAN.rows) {
      assert.equal(row.program, "case");
      assert.equal(row.op, "meta");
      assert.equal(row.plan, row.candidates.ascii ? "allow" : "deny", row.id);
    }
    assert.equal(CASE_PLAN.rowsOf("case").length, CASE_ROWS.length);
  });

  it("predicts every row for every candidate as the reference mapping does", () => {
    for (const row of CASE_ROWS)
      for (const candidate of CANDIDATES)
        assert.equal(
          predictRow(row, candidate, P),
          reference(row, candidate),
          `${row.id}/${candidate}`,
        );
  });

  it("states the known answers by hand for the rows that tell the candidates apart", () => {
    const by = Object.fromEntries(CASE_ROWS.map((r) => [r.id, r.candidates]));
    const only = (a, f, s) => ({ ascii: a, full: f, simple: s });
    assert.deepEqual(by["ctl-upper-true"], only(true, true, true));
    assert.deepEqual(by["ctl-upper-false"], only(false, false, false));
    assert.deepEqual(by["acute-lower-same"], only(true, false, false));
    assert.deepEqual(by["acute-lower-mapped"], only(false, true, true));
    assert.deepEqual(by["sharp-upper-full"], only(false, true, false));
    assert.deepEqual(by["sharp-upper-same"], only(true, false, true));
    assert.deepEqual(by["dotted-lower-full"], only(false, true, false));
    assert.deepEqual(by["dotted-lower-simple"], only(false, false, true));
    assert.deepEqual(by["dotted-lower-same"], only(true, false, false));
    assert.deepEqual(by["sigma-final"], only(false, true, false));
    assert.deepEqual(by["sigma-plain"], only(false, false, true));
    assert.deepEqual(by["sigma-same"], only(true, false, false));
    assert.deepEqual(by["comb-upper"], only(true, true, true));
    assert.deepEqual(by["comb-upper-composed"], only(false, false, false));
    assert.deepEqual(by["emoji-upper"], only(true, true, true));
    assert.deepEqual(by["fullwidth-upper-mapped"], only(false, true, true));
    assert.deepEqual(by["rt-lower-same"], only(true, false, false));
    assert.deepEqual(by["rt-res-lower-differs"], only(false, true, true));
  });

  it("gives every concept a row that reads true under each candidate, so a refusal is never an error in disguise", () => {
    const groups = Map.groupBy(
      CASE_ROWS.filter((r) => !r.control),
      (r) => r.group,
    );
    assert.ok(groups.size >= 10);
    for (const [group, rows] of groups) {
      for (const candidate of CANDIDATES) {
        // A concept on which two candidates agree on every row is described by the candidates that
        // do differ; here each concept must have a true row for every candidate that maps it at all.
        const trues = rows.filter((r) => r.candidates[candidate]);
        const falses = rows.filter((r) => !r.candidates[candidate]);
        assert.ok(trues.length > 0, `${group}/${candidate} has no true row`);
        assert.ok(falses.length > 0 || rows.length === 1, `${group}/${candidate} has no false row`);
      }
    }
  });

  it("keeps the controls true or false the same way under every candidate", () => {
    const controls = CASE_ROWS.filter((r) => r.control);
    assert.ok(controls.length >= 7);
    assert.ok(controls.some((r) => r.candidates.ascii));
    assert.ok(controls.some((r) => !r.candidates.ascii));
    for (const row of controls) {
      assert.equal(row.candidates.full, row.candidates.ascii, row.id);
      assert.equal(row.candidates.simple, row.candidates.ascii, row.id);
    }
  });

  it("writes the rule sources with the raw characters, in one service block, one match per row", () => {
    const source = ruleSource(P);
    assert.equal(source, CASE_PLAN.programs[0].source(P));
    assert.ok(source.startsWith("rules_version = '2';\nservice firebase.storage {"));
    assert.ok(source.includes("match /b/{bucket}/o {"));
    assert.ok(source.includes(`match /${P}/mk/a {\n      allow read: if true;\n    }`));
    assert.ok(source.includes(`match /${P}/acute-lower-mapped/x {`));
    assert.ok(source.includes("'" + cp(0xc9) + "'.lower() == '" + cp(0xe9) + "'"));
    assert.ok(source.includes("'" + cp(0x391, 0x3a3) + "'.lower() == '" + cp(0x3b1, 0x3c2) + "'"));
    assert.ok(source.includes("'e" + cp(0x301) + "'.upper() == 'E" + cp(0x301) + "'"));
    assert.ok(source.includes("'\u{1f525}a'.upper() == '\u{1f525}A'"));
    assert.ok(source.includes("'" + cp(0xff41) + "'.upper() == '" + cp(0xff21) + "'"));
    assert.ok(
      source.includes(
        `match /${P}/rt-lower-same/{n} {\n      allow read: if n.lower() == '${cp(0xc9)}';`,
      ),
    );
    assert.ok(
      source.includes(
        `match /${P}/rt-res-lower-same/{n} {\n      allow read: if resource.name.lower() == resource.name;`,
      ),
    );
    assert.equal((source.match(/allow read:/g) ?? []).length, CASE_ROWS.length + 1);
    assert.ok(!source.includes("\\u"), "no escape sequence is sent");
    assert.ok(Buffer.byteLength(source) < 40_000);
  });

  it("keeps its own source file ASCII, so no editor or tool can normalize a probe", () => {
    const text = readFileSync(
      fileURLToPath(new URL("./storage-rules-s9/plan-case.mjs", import.meta.url)),
      "utf8",
    );
    assert.ok([...text].every((c) => c.charCodeAt(0) < 0x80));
  });

  it("derives the request counts from the table and keeps the worst case above the expected one", () => {
    const expected = CASE_PLAN.expectedRequests(2);
    const bounds = CASE_PLAN.staticBounds(2);
    assert.ok(expected > 2 * 2 * CASE_ROWS.length);
    assert.ok(bounds.main > expected);
    assert.ok(bounds.total > bounds.main);
    assert.equal(
      CASE_PLAN.plannedNames(runId, 2).length,
      2 * Object.keys(CASE_PLAN.objects).length,
    );
    assert.ok(CASE_PLAN.readbackCap(2) >= 2 * Object.keys(CASE_PLAN.objects).length + 6);
    assert.ok(CASE_PLAN.estimatedUsd <= 0.1);
  });
});

describe("buildPlan keeps the s9 family exactly as it was", () => {
  it("builds the s9 plan from the same tables and the same numbers", () => {
    assert.equal(S9_PLAN.id, "s9");
    assert.equal(S9_PLAN.taskId, "STORAGE-RULES-S9");
    assert.equal(S9_PLAN.prefixRoot, "storage-rules-s9");
    assert.equal(S9_PLAN.expectedRequests(2), 340);
    assert.equal(S9_PLAN.staticBounds(2).main, 1036);
    assert.equal(S9_PLAN.staticBounds(2).total, 1152);
    assert.equal(S9_PLAN.rows.length, 32);
    assert.equal(S9_PLAN.loadOnly.length, 3);
  });

  it("refuses a plan whose rows name an object or program that does not exist", () => {
    const base = {
      id: "t",
      taskId: "T",
      prefixRoot: "t",
      estimatedUsd: 0.01,
      localBucket: "demo-t.appspot.com",
      objects: { mk: { name: (p) => `${p}/mk`, body: "m" } },
      programs: [{ id: "p", marker: "mk", objects: ["mk"], source: () => "x" }],
      loadOnly: [],
      rows: [],
    };
    assert.doesNotThrow(() => buildPlan(base));
    assert.throws(
      () => buildPlan({ ...base, rows: [{ program: "p", id: "r", op: "meta", object: "nope" }] }),
      /object/,
    );
    assert.throws(
      () => buildPlan({ ...base, rows: [{ program: "q", id: "r", op: "meta", object: "mk" }] }),
      /program/,
    );
    assert.throws(
      () =>
        buildPlan({
          ...base,
          programs: [{ id: "p", marker: "zz", objects: ["mk"], source: () => "x" }],
        }),
      /marker/,
    );
  });
});

describe("the case family tables in detail", () => {
  it("names each object by its row: x for a literal row, the character for the others", () => {
    for (const row of CASE_ROWS) {
      const leaf = row.kind === "literal" ? "x" : row.objectName;
      assert.equal(CASE_PLAN.objectName(row.object, P), `${P}/${row.id}/${leaf}`, row.id);
    }
    assert.equal(CASE_PLAN.objectName("mkA", P), `${P}/mk/a`);
  });

  it("gives controls the group ctl and nobody else, and every row one of four relations", () => {
    for (const row of CASE_ROWS) {
      assert.equal(row.group === "ctl", row.control, row.id);
      assert.equal(row.control, row.id.startsWith("ctl-"), row.id);
      assert.ok(["eq", "size", "same", "differs"].includes(row.rel), `${row.id} ${row.rel}`);
    }
    assert.deepEqual(
      [...new Set(CASE_ROWS.map((r) => r.group))],
      [
        "ctl",
        "acute",
        "sharp",
        "capsharp",
        "dotted",
        "dotless",
        "sigma",
        "alpha",
        "comb",
        "emoji",
        "fullwidth",
        "rt-lower",
        "rt-sharp",
        "rt-res",
      ],
    );
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(Object.groupBy(CASE_ROWS, (r) => r.group)).map(([k, v]) => [k, v.length]),
      ),
      {
        ctl: 7,
        acute: 4,
        sharp: 2,
        capsharp: 2,
        dotted: 3,
        dotless: 2,
        sigma: 3,
        alpha: 2,
        comb: 2,
        emoji: 3,
        fullwidth: 3,
        "rt-lower": 2,
        "rt-sharp": 2,
        "rt-res": 2,
      },
    );
  });

  it("uses the relation of each kind: size for the counted rows, same and differs for resource.name", () => {
    const rel = Object.fromEntries(CASE_ROWS.map((r) => [r.id, r.rel]));
    for (const id of [
      "ctl-size-nonascii",
      "ctl-size-emoji",
      "dotted-lower-full",
      "emoji-lower-size",
    ])
      assert.equal(rel[id], "size", id);
    assert.equal(rel["rt-res-lower-same"], "same");
    assert.equal(rel["rt-res-lower-differs"], "differs");
    assert.equal(CASE_ROWS.filter((r) => r.rel === "eq").length, CASE_ROWS.length - 6);
  });

  it("stores the marker as a, every other object as its row id, and states its price and local bucket", () => {
    assert.equal(CASE_PLAN.objects.mkA.body, "a");
    for (const row of CASE_ROWS) assert.equal(CASE_PLAN.objects[row.object].body, row.id);
    assert.equal(CASE_PLAN.estimatedUsd, 0.05);
    assert.equal(CASE_PLAN.localBucket, "demo-storage-case.appspot.com");
  });

  it("predicts a row that applies no function by the text alone, under every candidate", () => {
    const plain = { kind: "literal", fn: null, input: "abc", rel: "eq", operand: "abc" };
    const sized = { kind: "literal", fn: null, input: "ab", rel: "size", operand: 2 };
    for (const candidate of CANDIDATES) {
      assert.equal(predictRow(plain, candidate), true, candidate);
      assert.equal(predictRow(sized, candidate), true, candidate);
    }
  });

  it("agrees with the reference on a mapping the rows do not reach: every code point, both functions", () => {
    for (let point = 0; point < 0x2fff; point += 1) {
      if (point >= 0xd800 && point <= 0xdfff) continue;
      const text = String.fromCodePoint(point);
      for (const fn of ["lower", "upper"])
        for (const candidate of CANDIDATES) {
          const row = {
            kind: "literal",
            fn,
            input: text,
            rel: "eq",
            operand: MAPS[candidate](text, fn),
          };
          assert.equal(
            predictRow(row, candidate),
            true,
            `${point.toString(16)} ${fn} ${candidate}`,
          );
          const other = { ...row, operand: `${row.operand}.` };
          assert.equal(predictRow(other, candidate), false);
        }
    }
  });

  it("states the cap of a recovery as the cleanup of a full run plus twenty", () => {
    assert.equal(CASE_PLAN.recoveryCap(2), CASE_PLAN.staticBounds(2).cleanup + 20);
    assert.equal(CASE_PLAN.recoveryCap(1), CASE_PLAN.staticBounds(1).cleanup + 20);
    assert.equal(CASE_PLAN.recoveryCap(), CASE_PLAN.recoveryCap(2));
    assert.equal(S9_PLAN.recoveryCap(2), S9_PLAN.staticBounds(2).cleanup + 20);
  });
});

describe("buildPlan refuses a program whose object does not exist", () => {
  it("names the object", () => {
    const base = {
      id: "t",
      taskId: "T",
      prefixRoot: "t",
      estimatedUsd: 0.01,
      localBucket: "demo-t.appspot.com",
      objects: { mk: { name: (p) => `${p}/mk`, body: "m" } },
      loadOnly: [],
      rows: [],
    };
    assert.throws(
      () =>
        buildPlan({
          ...base,
          programs: [{ id: "p", marker: "mk", objects: ["mk", "gone"], source: () => "x" }],
        }),
      /program p: unknown object gone/,
    );
  });
});
