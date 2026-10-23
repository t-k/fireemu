import assert from "node:assert/strict";
import test from "node:test";

import { CALIBRATION_PHASES } from "./fs-ent-pipeline/text-calibration.mjs";

const QUERY_IDS = ["fox", "quick", "conjunction", "duplicate", "phrase", "enhancement-disabled"];
const BASE_IDS = "abcdefghijklmnop".split("");
const BASE_PATHS = BASE_IDS.map((id) => `textobs1/c-${id}`);

function wordCount(value) {
  return value === "" ? 0 : value.trim().split(/\s+/).length;
}

function assertPhase(phase, expectedCount, expectedFields) {
  assert.deepEqual(phase.indexFields, expectedFields);
  assert.equal(phase.seed.length, expectedCount);
  assert.equal(new Set(phase.seed.map(([path]) => path)).size, expectedCount);
  for (const [path, fields] of phase.seed) {
    assert.match(path, /^textobs1\/c-[a-z0-9-]+$/);
    for (const [name, value] of Object.entries(fields)) {
      assert.ok(
        ["stringValue", "integerValue", "nullValue"].some((key) => key in value),
        name,
      );
    }
  }
  assert.deepEqual(
    phase.queries.map(({ id }) => id),
    QUERY_IDS,
  );
  for (const query of phase.queries) {
    assert.equal(typeof query.text, "string");
    const score = { functionValue: { name: "score", args: [] } };
    const expectedOptions = {
      add_fields: { mapValue: { fields: { rank: score } } },
      sort: {
        arrayValue: {
          values: [
            {
              mapValue: {
                fields: {
                  expression: score,
                  direction: { stringValue: "descending" },
                },
              },
            },
          ],
        },
      },
    };
    if (query.id === "enhancement-disabled") {
      expectedOptions.query_enhancement = { stringValue: "disabled" };
    }
    assert.deepEqual(query.options, expectedOptions);
  }
}

function frequencies(seed, field, token) {
  return seed.map(([path, fields]) => {
    const value = fields[field]?.stringValue ?? "";
    return [path, value.split(/\s+/).filter((word) => word === token).length];
  });
}

test("calibration phases have exact field sets, document counts, and scoped identities", () => {
  assert.deepEqual(
    CALIBRATION_PHASES.map(({ id }) => id),
    [
      "one-field",
      "two-fields",
      "document-frequency-control",
      "padded-corpus-control",
      "denominator-control",
    ],
  );
  assertPhase(CALIBRATION_PHASES[0], 16, ["title"]);
  for (const phase of CALIBRATION_PHASES.slice(1, 4)) {
    assertPhase(phase, phase.id === "padded-corpus-control" ? 24 : 16, ["title", "body"]);
  }
  assertPhase(CALIBRATION_PHASES[4], 19, ["title", "body"]);

  const uniqueIds = new Set(CALIBRATION_PHASES.flatMap(({ seed }) => seed.map(([path]) => path)));
  assert.equal(uniqueIds.size, 27);
});

test("the first two phases share the 16-document seed with typed values", () => {
  const [oneField, twoFields] = CALIBRATION_PHASES;
  assert.deepEqual(oneField.seed, twoFields.seed);
  assert.deepEqual(
    twoFields.seed.map(([path]) => path),
    BASE_PATHS,
  );

  const byPath = new Map(twoFields.seed);
  assert.deepEqual(byPath.get("textobs1/c-n"), {
    title: { stringValue: "neutral" },
    body: { stringValue: "fox" },
  });
  assert.deepEqual(byPath.get("textobs1/c-o"), {
    title: { stringValue: "neutral" },
    body: { stringValue: "fox fox fox" },
  });
  assert.deepEqual(byPath.get("textobs1/c-p"), {
    title: { stringValue: "fox fox" },
    body: { stringValue: "fox neutral" },
  });
});

test("document-frequency control swaps title terms without changing field lengths", () => {
  const baseline = CALIBRATION_PHASES[1].seed;
  const controlled = CALIBRATION_PHASES[2].seed;
  const baselineByPath = new Map(baseline);
  const controlledByPath = new Map(controlled);

  for (const path of BASE_PATHS) {
    for (const field of ["title", "body"]) {
      assert.equal(
        wordCount(controlledByPath.get(path)[field].stringValue),
        wordCount(baselineByPath.get(path)[field].stringValue),
      );
    }
  }
  assert.equal(controlledByPath.get("textobs1/c-f").title.stringValue, "fox");
  assert.equal(controlledByPath.get("textobs1/c-m").title.stringValue, "quick");
  assert.equal(
    frequencies(controlled, "title", "fox").find(([path]) => path === "textobs1/c-f")[1],
    frequencies(baseline, "title", "fox").find(([path]) => path === "textobs1/c-f")[1] + 1,
  );
  assert.equal(
    frequencies(controlled, "title", "quick").find(([path]) => path === "textobs1/c-m")[1],
    frequencies(baseline, "title", "quick").find(([path]) => path === "textobs1/c-m")[1] + 1,
  );
  for (const id of BASE_IDS.filter((id) => !["f", "m"].includes(id))) {
    assert.deepEqual(
      controlledByPath.get(`textobs1/c-${id}`),
      baselineByPath.get(`textobs1/c-${id}`),
    );
  }
});

test("padded corpus adds eight unique low-signal documents", () => {
  const baseline = CALIBRATION_PHASES[1].seed;
  const padded = CALIBRATION_PHASES[3].seed;
  assert.deepEqual(padded.slice(0, baseline.length), baseline);
  assert.deepEqual(
    padded.slice(baseline.length).map(([path, fields]) => [path, fields.title.stringValue]),
    Array.from({ length: 8 }, (_, index) => [
      `textobs1/c-pad-${index + 1}`,
      `padding ${Array(20).fill("filler").join(" ")}`,
    ]),
  );
});

test("denominator control distinguishes empty, omitted, integer, and null fields", () => {
  const seed = CALIBRATION_PHASES[4].seed;
  const base = CALIBRATION_PHASES[1].seed;
  assert.deepEqual(seed.slice(0, base.length), base);
  const byPath = new Map(seed);
  assert.deepEqual(byPath.get("textobs1/c-q"), {});
  assert.deepEqual(byPath.get("textobs1/c-r"), {
    title: { integerValue: "7" },
    body: { nullValue: null },
  });
  assert.deepEqual(byPath.get("textobs1/c-s"), {
    title: { stringValue: "" },
    body: { stringValue: "" },
  });
});

test("all phases use independent query objects with fixed texts and score options", () => {
  assert.deepEqual(
    CALIBRATION_PHASES[0].queries.map(({ id, text }) => [id, text]),
    [
      ["fox", "fox"],
      ["quick", "quick"],
      ["conjunction", "quick fox"],
      ["duplicate", "fox fox"],
      ["phrase", '"quick fox"'],
      ["enhancement-disabled", "fox"],
    ],
  );
  const optionObjects = CALIBRATION_PHASES.flatMap((phase) =>
    phase.queries.map((query) => query.options),
  );
  assert.equal(new Set(optionObjects).size, optionObjects.length);
  const addFieldObjects = CALIBRATION_PHASES.flatMap((phase) =>
    phase.queries.map((query) => query.options.add_fields),
  );
  assert.equal(new Set(addFieldObjects).size, addFieldObjects.length);
  for (const phase of CALIBRATION_PHASES) {
    assert.notEqual(phase.queries[0].options, phase.queries[1].options);
    assert.notEqual(phase.queries[0].options.add_fields, phase.queries[1].options.add_fields);
  }
  assert.notEqual(CALIBRATION_PHASES[0].seed, CALIBRATION_PHASES[1].seed);
  assert.notEqual(CALIBRATION_PHASES[0].seed[0][1], CALIBRATION_PHASES[1].seed[0][1]);
  assert.notEqual(CALIBRATION_PHASES[0].seed[0][1].title, CALIBRATION_PHASES[1].seed[0][1].title);
});

test("frequency negative control detects a semantic mutation against a no-op baseline", () => {
  const baseline = structuredClone(CALIBRATION_PHASES[2].seed);
  const baselineFrequency = frequencies(baseline, "title", "fox");
  assert.deepEqual(frequencies(structuredClone(baseline), "title", "fox"), baselineFrequency);

  const mutant = structuredClone(baseline);
  mutant.find(([path]) => path === "textobs1/c-f")[1].title.stringValue = "padding";
  assert.notDeepEqual(frequencies(mutant, "title", "fox"), baselineFrequency);
});
