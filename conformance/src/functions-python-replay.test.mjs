import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { compare, families, validate } from "./functions-python/compare.mjs";
const record = JSON.parse(
  readFileSync(new URL("../../spec/compatibility/closure/FUNCTIONS-PYTHON.json", import.meta.url)),
);
const fixture = JSON.parse(
  readFileSync(new URL("../functions-python/fixtures/observations.json", import.meta.url)),
);

test("complete projections reject value, presence, extra fields, type and array-length differences", () => {
  for (const [expected, actual] of [
    [{ n: 1 }, { n: 2 }],
    [{ n: 1 }, {}],
    [{}, { n: 1 }],
    [{ n: 1 }, { n: "1" }],
    [[], [1]],
    [[1], []],
    [null, {}],
  ]) {
    assert.ok(compare(expected, actual, "strict").length);
  }
  assert.deepEqual(
    compare({ n: 1, nested: [null, true] }, { n: 1, nested: [null, true] }, "strict"),
    [],
  );
  assert.throws(() => compare({}, {}, "other"), /known profile/);
});
for (const difference of record.declaredDifferences) {
  test(`${difference.id}: exact declared field stays pending and its neighbor is a DIFF`, () => {
    for (const profile of difference.profiles) {
      const path = difference.fields[0];
      assert.deepEqual(compare({ [path]: 1 }, { [path]: 2 }, profile, [difference]), [
        { path, status: "PENDING_DIFFERENCE" },
      ]);
      assert.deepEqual(
        compare({ [`${path}-neighbor`]: 1 }, { [`${path}-neighbor`]: 2 }, profile, [difference]),
        [{ path: `${path}-neighbor`, status: "DIFF" }],
      );
    }
    const otherProfile = ["strict", "emulator"].find((p) => !difference.profiles.includes(p));
    if (otherProfile)
      assert.equal(
        compare({ [difference.fields[0]]: 1 }, { [difference.fields[0]]: 2 }, otherProfile, [
          difference,
        ])[0].status,
        "DIFF",
      );
  });
}
test("masked task body remains bytes, not JSON equality", () => {
  const body = fixture.observations
    .find((r) => r.condition === "tasks-events")
    .frames.find((f) => f.bodyText).bodyText;
  const value = JSON.parse(body);
  const reordered = JSON.stringify({
    data: Object.fromEntries(Object.entries(value.data).toReversed()),
  });
  assert.notEqual(body, reordered);
  assert.deepEqual(compare({ body }, { body: reordered }, "strict"), [
    { path: "body", status: "DIFF" },
  ]);
});
if (process.env.PYTHON_PARENT_PICT) {
  const [head, ...rows] = readFileSync(process.env.PYTHON_PARENT_PICT, "utf8")
    .trim()
    .split(/\r?\n/)
    .map((r) => r.split("\t"));
  for (const [i, row] of rows.entries()) {
    const c = Object.fromEntries(head.map((k, n) => [k, row[n]]));
    test(`PICT ${i}: ${row.join("/")}`, () => {
      assert.ok(families.includes(c.Family));
      const observation = fixture.observations.find((r) => r.condition === c.Family);
      const expected = { frames: observation.frames.length, pass: observation.observedPasses };
      const actual = structuredClone(expected);
      if (c.Alteration === "missing") delete actual.frames;
      if (c.Alteration === "wrong") actual.frames += 1;
      if (c.Alteration === "extra") actual.extra = true;
      assert.equal(compare(expected, actual, c.Profile).length > 0, c.Alteration !== "exact");
      const candidate = structuredClone(record);
      if (c.Decision === "answered") candidate.scopeDecisions[0].answer = "strict";
      const corpus = JSON.parse(
        readFileSync(new URL("../functions-python/corpus.json", import.meta.url)),
      );
      const bytes = readFileSync(
        new URL("../functions-python/fixtures/observations.json", import.meta.url),
      );
      if (c.Decision === "answered") assert.throws(() => validate(candidate, corpus, bytes), /PY1/);
      else validate(candidate, corpus, bytes);
    });
  }
}

test("seeded projection properties preserve equality and detect every single-leaf change", () => {
  let state = 1729;
  const next = () => (state = (Math.imul(state, 1664525) + 1013904223) >>> 0);
  for (let i = 0; i < 128; i += 1) {
    const value = {
      nested: { count: next(), present: Boolean(next() & 1) },
      values: [next(), null],
    };
    assert.deepEqual(compare(value, structuredClone(value), "strict"), []);
    const changed = structuredClone(value);
    changed.nested.count += 1;
    assert.deepEqual(compare(value, changed, "strict"), [{ path: "nested.count", status: "DIFF" }]);
    assert.deepEqual(compare(changed, value, "emulator"), [
      { path: "nested.count", status: "DIFF" },
    ]);
  }
});
