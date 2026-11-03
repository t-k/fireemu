// The coverage table of the pipeline lane (fs-ent-pipeline/coverage.mjs): which rows may stay a
// raw MISMATCH or UNKNOWN while the lane exits 0, and how far each answer may differ. Every rule
// has a case that passes and cases that fail; nothing here sends a request.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  COVERAGE,
  CLOCK_ROW,
  coveredBy,
  judgeCoverage,
  laneExitCode,
  stepsNeededBy,
} from "./fs-ent-pipeline/coverage.mjs";
import { PROGRAMS } from "./fs-ent-pipeline/corpus.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const FIXTURE = read("../fs-ent-pipeline-production.json").programs;
const POLICY = read("./fs-ent-pipeline/o7-order-policy-data.json");
const COMPARISON = read(
  "../../spec/compatibility/closure/evidence/FS-PIPELINE-current-comparison.json",
);
const clone = (value) => structuredClone(value);
const split = (row) => [row.slice(0, row.lastIndexOf("#")), row.slice(row.lastIndexOf("#") + 1)];
const O7_ROWS = POLICY.recipes.map((recipe) => recipe.id);
const O7_SELECTION = POLICY.recipes.filter((recipe) => recipe.mode === "selection");
const O7_FULL = POLICY.recipes.filter((recipe) => recipe.mode === "full");
const V_DESC = "fs-ent-pipeline/o6/sort-kinds-cross#v-desc";
const TIES = "fs-ent-pipeline/o6/sort-ties#g-asc-limit2";
const NESTING = [
  "fs-ent-pipeline/o8a/nesting-main#chain-48-grpc",
  "fs-ent-pipeline/o8a/nesting-main#chain-100-grpc",
];

/** The lane's inputs for one row: the program, the saved production rows and the local answers. */
function input(row, { status = "MISMATCH", local } = {}) {
  const [programId] = split(row);
  const program = PROGRAMS.find((item) => item.id === programId);
  const saved = clone(FIXTURE[programId]);
  const localSteps = clone(saved.steps);
  local?.(localSteps, saved);
  return { row, status, program, saved, localSteps };
}
const results = (steps, row) => steps[split(row)[1]].body[0].results;
const accepted = (value, decision, rule) => {
  assert.equal(value?.decision, decision, JSON.stringify(value));
  assert.equal(value.rule, rule);
  assert.equal(typeof value.proof, "string");
};
const rejected = (value) => {
  assert.ok(value?.rejected, JSON.stringify(value));
};

test("one table names every covered row, with its decision", () => {
  assert.equal(COVERAGE.size, 28);
  assert.equal(O7_ROWS.length, 23);
  for (const recipe of POLICY.recipes)
    assert.deepEqual(COVERAGE.get(recipe.id), {
      decision: recipe.mode === "selection" ? "2214" : "2211",
      rule: "o7-groups",
    });
  for (const row of [V_DESC, TIES])
    assert.deepEqual(COVERAGE.get(row), { decision: "2114", rule: "o6-tie" });
  assert.deepEqual(COVERAGE.get(CLOCK_ROW), { decision: "2211", rule: "clock-value" });
  for (const row of NESTING)
    assert.deepEqual(COVERAGE.get(row), {
      decision: "nesting-observation",
      rule: "later-observation",
    });
  const corpus = new Set(PROGRAMS.flatMap((p) => p.steps.map((s) => `${p.id}#${s.id}`)));
  for (const row of COVERAGE.keys()) assert.ok(corpus.has(row), row);
});

test("the table covers exactly the rows of the current comparison that are not MATCH-like", () => {
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC"]);
  const open = COMPARISON.rows.filter((row) => !passing.has(row.status)).map((row) => row.row);
  assert.deepEqual(open.toSorted(), [...COVERAGE.keys()].toSorted());
  for (const row of COMPARISON.rows) {
    const entry = COVERAGE.get(row.row);
    if (!entry) continue;
    assert.equal(row.status, entry.rule === "later-observation" ? "UNKNOWN" : "MISMATCH", row.row);
  }
});

test("O-7: the same groups in another order are covered, for every row", () => {
  for (const recipe of POLICY.recipes) {
    accepted(
      coveredBy(input(recipe.id)),
      recipe.mode === "selection" ? "2214" : "2211",
      "o7-groups",
    );
  }
  for (const recipe of O7_FULL.filter((item) => !item.sort)) {
    const reversed = input(recipe.id, {
      local: (steps) => results(steps, recipe.id).reverse(),
    });
    accepted(coveredBy(reversed), "2211", "o7-groups");
  }
});

test("O-7: a group that differs, is missing, is doubled or is added is not covered", () => {
  const faults = {
    changed: (rows) => {
      const key = Object.keys(rows[0].fields)[0];
      rows[0].fields[key] = { stringValue: "changed" };
    },
    dropped: (rows) => rows.pop(),
    doubled: (rows) => {
      if (rows.length < 2) throw Error("needs two groups");
      rows[rows.length - 1] = clone(rows[0]);
    },
    added: (rows) => rows.push(clone(rows[0])),
  };
  for (const recipe of O7_FULL) {
    for (const [name, fault] of Object.entries(faults)) {
      const [programId, stepId] = split(recipe.id);
      const probe = input(recipe.id, { local: (steps) => fault(steps[stepId].body[0].results) });
      const count = FIXTURE[programId].steps[stepId].body[0].results.length;
      if (name === "doubled" && count < 2) continue;
      rejected(coveredBy(probe));
    }
  }
});

test("O-7: another shell, status, round or recording is not covered", () => {
  for (const recipe of O7_ROWS) {
    const [programId, stepId] = split(recipe);
    rejected(
      coveredBy(
        input(recipe, { local: (steps) => (steps[stepId].body[0].executionTime = "<t9>") }),
      ),
    );
    rejected(coveredBy(input(recipe, { local: (steps) => (steps[stepId].status = 500) })));
    rejected(coveredBy(input(recipe, { local: (steps) => delete steps[stepId].body[0].results })));
    // A second round that differs from the first is not the recorded variation.
    const rounds = input(recipe);
    rounds.saved.second = {
      [stepId]: {
        ...clone(rounds.saved.steps[stepId]),
        status: 200,
        body: [{ executionTime: "<t1>", results: [] }],
      },
    };
    rejected(coveredBy(rounds));
    // The saved production row is pinned by its digest.
    const edited = input(recipe);
    edited.saved.steps[stepId].body[0].results.push({ fields: {} });
    edited.localSteps[stepId] = clone(edited.saved.steps[stepId]);
    rejected(coveredBy(edited));
    assert.ok(programId);
  }
  // The covered row must be a MISMATCH.
  for (const status of ["UNKNOWN", "INDETERMINATE", "MATCH_NONDETERMINISTIC"])
    rejected(coveredBy(input(O7_ROWS[0], { status })));
});

test("O-7: a legal selection needs the companion groups, a legal count and the recorded companion", () => {
  assert.equal(O7_SELECTION.length, 3);
  for (const recipe of O7_SELECTION) {
    const companion = split(recipe.companion)[1];
    const [, stepId] = split(recipe.id);
    // A row that is not among the companion's groups.
    rejected(
      coveredBy(
        input(recipe.id, {
          local: (steps) => {
            const row = steps[stepId].body[0].results[0];
            const key = Object.keys(row.fields)[0];
            row.fields[key] = { stringValue: "not an eligible group" };
          },
        }),
      ),
    );
    // One group more than production selected.
    rejected(
      coveredBy(
        input(recipe.id, {
          local: (steps) =>
            steps[stepId].body[0].results.push(clone(steps[stepId].body[0].results[0])),
        }),
      ),
    );
    // The companion answered differently from its recording.
    rejected(
      coveredBy(
        input(recipe.id, {
          local: (steps) => steps[companion].body[0].results.pop(),
        }),
      ),
    );
  }
});

test("O-6 sort ties (2114): only the tied rows may permute", () => {
  accepted(coveredBy(input(V_DESC)), "2114", "o6-tie");
  const swapTail = input(V_DESC, {
    local: (steps) => {
      const rows = results(steps, V_DESC);
      [rows[14], rows[15]] = [rows[15], rows[14]];
    },
  });
  accepted(coveredBy(swapTail), "2114", "o6-tie");
  const faults = {
    "an ordered row moves": (rows) => ([rows[0], rows[1]] = [rows[1], rows[0]]),
    "a tied row is replaced": (rows) => (rows[15] = clone(rows[3])),
    "a row is lost": (rows) => rows.pop(),
    "a typed value changes": (rows) => {
      const key = Object.keys(rows[5].fields)[0];
      rows[5].fields[key] = { stringValue: "changed" };
    },
  };
  for (const [name, fault] of Object.entries(faults))
    rejected(coveredBy(input(V_DESC, { local: (steps) => fault(results(steps, V_DESC)) })), name);
  rejected(coveredBy(input(V_DESC, { local: (steps) => (steps["seed-vector"].status = 500) })));
});

test("O-6 limit over ties (2114): two distinct rows of the three eligible ones", () => {
  const companion = FIXTURE["fs-ent-pipeline/o6/sort-ties"].steps["g-asc"].body[0].results;
  const choose = (...picks) =>
    input(TIES, {
      local: (steps) => {
        steps["g-asc-limit2"].body[0].results = picks.map((index) => clone(companion[index]));
      },
    });
  for (const picks of [
    [0, 1],
    [0, 2],
    [2, 1],
  ])
    accepted(coveredBy(choose(...picks)), "2114", "o6-tie");
  rejected(coveredBy(choose(0, 0)));
  rejected(coveredBy(choose(0, 3)));
  rejected(coveredBy(choose(0)));
  rejected(coveredBy(choose(0, 1, 2)));
  rejected(coveredBy(input(TIES, { local: (steps) => steps["g-asc"].body[0].results.reverse() })));
});

test("the clock-dependent value is the only allowed difference of timestamp-diff-now", () => {
  const value = (steps, integerValue) => {
    steps["timestamp-diff-now"].body[0].results[0].fields.v = integerValue;
  };
  accepted(
    coveredBy(input(CLOCK_ROW, { local: (steps) => value(steps, { integerValue: "1793664245" }) })),
    "2211",
    "clock-value",
  );
  const faults = {
    "not an integer": (steps) => value(steps, { doubleValue: 1.5 }),
    "a string": (steps) => value(steps, { stringValue: "1793664245" }),
    "a leading zero": (steps) => value(steps, { integerValue: "01" }),
    "an extra key": (steps) => value(steps, { integerValue: "1", nullValue: null }),
    "an extra field": (steps) => {
      steps["timestamp-diff-now"].body[0].results[0].fields.w = { integerValue: "1" };
    },
    "an extra row": (steps) =>
      steps["timestamp-diff-now"].body[0].results.push({ fields: { v: { integerValue: "1" } } }),
    "another shell": (steps) => (steps["timestamp-diff-now"].body[0].executionTime = "<t9>"),
    "another status": (steps) => (steps["timestamp-diff-now"].status = 400),
  };
  for (const [name, fault] of Object.entries(faults))
    rejected(coveredBy(input(CLOCK_ROW, { local: fault })), name);
  rejected(coveredBy(input(CLOCK_ROW, { status: "UNKNOWN" })));
});

test("the two gRPC chains are covered while both sides are the recorder's client failure", () => {
  for (const row of NESTING) {
    const [, stepId] = split(row);
    const unknown = (steps) => {
      steps[stepId] = { ...clone(FIXTURE["fs-ent-pipeline/o8a/nesting-main"].steps[stepId]) };
      delete steps[stepId].unknown;
    };
    accepted(
      coveredBy(input(row, { status: "UNKNOWN", local: unknown })),
      "nesting-observation",
      "later-observation",
    );
    // fireemu answers something else: the lane no longer compares what the observation pins.
    rejected(
      coveredBy(
        input(row, {
          status: "UNKNOWN",
          local: (steps) => {
            unknown(steps);
            steps[stepId].code = 3;
          },
        }),
      ),
    );
    rejected(coveredBy(input(row, { status: "MISMATCH", local: unknown })));
    rejected(coveredBy(input(row, { status: "MATCH", local: unknown })));
    // A production row that is not the recorder's own failure is not this row.
    const answered = input(row, { status: "UNKNOWN", local: unknown });
    delete answered.saved.steps[stepId].unknown;
    rejected(coveredBy(answered));
  }
});

test("the lane judges coverage: an uncovered row, a lost row or a refused answer fails", () => {
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC", "DIVERGENCE_APPROVED"]);
  const table = new Map([
    ["a", { decision: "d", rule: "r" }],
    ["b", { decision: "d", rule: "r" }],
  ]);
  const cover = (row) => (row.row === "a" ? { decision: "d", rule: "r" } : undefined);
  const base = [
    { row: "a", status: "MISMATCH" },
    { row: "b", status: "MATCH" },
    { row: "c", status: "MATCH_NONDETERMINISTIC" },
  ];
  const clean = judgeCoverage(base, passing, cover, table);
  assert.deepEqual(clean.uncovered, []);
  assert.deepEqual(clean.missing, []);
  assert.deepEqual(
    clean.covered.map((item) => item.row),
    ["a"],
  );
  // Any other MISMATCH, UNKNOWN or INDETERMINATE row fails.
  for (const status of ["MISMATCH", "UNKNOWN", "INDETERMINATE", "MISSING", "STALE_FIXTURE"])
    assert.deepEqual(
      judgeCoverage([...base, { row: "x", status }], passing, cover, table).uncovered.map(
        (item) => item.row,
      ),
      ["x"],
      status,
    );
  // A covered row whose answer goes beyond the allowance is reported with its reason.
  const refused = judgeCoverage(base, passing, () => ({ rejected: "a: too far" }), table);
  assert.deepEqual(refused.uncovered, [{ row: "a", status: "MISMATCH", reason: "a: too far" }]);
  // A table row the comparison no longer has fails.
  assert.deepEqual(judgeCoverage(base.slice(0, 1), passing, cover, table).missing, ["b"]);
  // A covered row that now matches needs no decision.
  assert.deepEqual(
    judgeCoverage(
      [
        { row: "a", status: "MATCH" },
        { row: "b", status: "MATCH" },
      ],
      passing,
      cover,
      table,
    ),
    { covered: [], uncovered: [], missing: [] },
  );
});

test("the lane exits 1 on an unsound check and 0 when every kept row is covered", () => {
  const clean = { covered: [{ row: "a" }], uncovered: [], missing: [] };
  const run = (change) => laneExitCode({ coverage: clean, orphans: [], failures: [], ...change });
  assert.equal(run({}), 0);
  assert.equal(run({ coverage: { ...clean, uncovered: [{ row: "x" }] } }), 1);
  assert.equal(run({ coverage: { ...clean, missing: ["y"] } }), 1);
  assert.equal(run({ orphans: ["program"] }), 1);
  assert.equal(run({ failures: ["session"] }), 1);
});

test("the steps an allowance reads are the row, its companion and its prelude", () => {
  assert.deepEqual(stepsNeededBy(V_DESC), ["v-desc", "seed-vector"]);
  assert.deepEqual(stepsNeededBy(TIES), ["g-asc-limit2", "g-asc"]);
  assert.deepEqual(stepsNeededBy(CLOCK_ROW), ["timestamp-diff-now"]);
  for (const recipe of O7_SELECTION)
    assert.deepEqual(stepsNeededBy(recipe.id), [split(recipe.id)[1], split(recipe.companion)[1]]);
});

test("a recorded failure that is not the recorder's client failure is not covered", () => {
  for (const row of NESTING) {
    const [, stepId] = split(row);
    const probe = input(row, {
      status: "UNKNOWN",
      local: (steps) => {
        steps[stepId] = { ...clone(FIXTURE["fs-ent-pipeline/o8a/nesting-main"].steps[stepId]) };
        delete steps[stepId].unknown;
        steps[stepId].code = 3;
      },
    });
    // Both sides report code 3 although the recorded row is the client failure (code 13).
    probe.saved.steps[stepId].code = 3;
    rejected(coveredBy(probe));
  }
});
