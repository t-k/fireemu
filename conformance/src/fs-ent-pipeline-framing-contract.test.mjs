import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { classifyCompactFraming, compactFramingStep } from "./fs-ent-pipeline/framing-summary.mjs";

const unit = (results, metadata = { executionTime: "<t1>" }) => ({ ...metadata, results });
const row = (transport, units, failed = false) =>
  transport === "grpc"
    ? { transport, code: failed ? 13 : 0, messages: units }
    : { status: failed ? 500 : 200, body: units };
const values = [{ n: 1 }, { n: 2 }, { n: 3 }];

for (const transport of ["rest", "grpc"]) {
  test(`${transport} accepts a different successful partition with equal ordered content`, () => {
    const expected = compactFramingStep(row(transport, [unit(values)]), "read");
    const actual = row(transport, [unit(values.slice(0, 1)), unit(values.slice(1))]);
    assert.equal(
      classifyCompactFraming(expected, undefined, actual).status,
      "MATCH_NONDETERMINISTIC",
    );
  });
  test(`${transport} retains strict content, metadata and terminal checks`, () => {
    const expected = compactFramingStep(row(transport, [unit(values)]), "read");
    for (const altered of [
      [values[1], values[0], values[2]],
      [{ n: "1" }, values[1], values[2]],
      [values[0], values[0], values[2]],
      values.slice(0, 2),
    ])
      assert.equal(
        classifyCompactFraming(expected, undefined, row(transport, [unit(altered)])).status,
        "MISMATCH",
      );
    assert.equal(
      classifyCompactFraming(
        expected,
        undefined,
        row(transport, [unit(values, { executionTime: "<t2>" })]),
      ).status,
      "MISMATCH",
    );
    assert.equal(
      classifyCompactFraming(expected, undefined, row(transport, [unit(values)], true)).status,
      "MISMATCH",
    );
    const corrupt = { ...expected, contentDigest: "0".repeat(64) };
    assert.equal(
      classifyCompactFraming(corrupt, undefined, row(transport, [unit(values)])).status,
      "MISMATCH",
    );
  });
  test(`${transport} leaves position-sensitive metadata on unseen partitions indeterminate`, () => {
    const first = { executionTime: "<t1>", transaction: "abc" };
    const expected = compactFramingStep(row(transport, [unit(values, first)]), "read");
    const local = row(transport, [unit(values.slice(0, 1), first), unit(values.slice(1), first)]);
    assert.equal(classifyCompactFraming(expected, undefined, local).status, "INDETERMINATE");
  });
}

test("seeded PICT combinations preserve the successful framing contract", () => {
  const combinations = [
    ["rest", "same", "unseen", "same", "success"],
    ["grpc", "same", "unseen", "same", "success"],
    ["rest", "truncated", "unseen", "same", "success"],
    ["grpc", "duplicate", "unseen", "changed", "failure"],
    ["rest", "reordered", "observed", "changed", "success"],
    ["grpc", "duplicate", "observed", "same", "success"],
    ["rest", "reordered", "unseen", "same", "failure"],
    ["grpc", "truncated", "observed", "changed", "failure"],
    ["grpc", "changed", "observed", "same", "failure"],
    ["grpc", "reordered", "unseen", "same", "failure"],
    ["rest", "changed", "unseen", "changed", "success"],
    ["grpc", "same", "observed", "changed", "failure"],
    ["rest", "duplicate", "observed", "changed", "success"],
  ];
  const variants = {
    same: values,
    changed: [{ n: 4 }, values[1], values[2]],
    reordered: [values[1], values[0], values[2]],
    duplicate: [values[0], values[0], values[2]],
    truncated: values.slice(0, 2),
  };
  for (const [transport, content, framing, metadata, outcome] of combinations) {
    const expected = compactFramingStep(row(transport, [unit(values)]), "read");
    const meta = { executionTime: metadata === "same" ? "<t1>" : "<t2>" };
    const data = variants[content];
    const units =
      framing === "observed"
        ? [unit(data, meta)]
        : [unit(data.slice(0, 1), meta), unit(data.slice(1), meta)];
    const result = classifyCompactFraming(
      expected,
      undefined,
      row(transport, units, outcome === "failure"),
    );
    const expectedStatus =
      outcome === "failure" || content !== "same" || metadata !== "same"
        ? "MISMATCH"
        : framing === "unseen"
          ? "MATCH_NONDETERMINISTIC"
          : "MATCH";
    assert.equal(result.status, expectedStatus, combinations.join());
  }
});

test("head and declared result count are independently checked", () => {
  const original = row("rest", [unit(values)]);
  const expected = compactFramingStep(original, "read");
  assert.equal(
    classifyCompactFraming(expected, undefined, { ...original, extra: true }).status,
    "MISMATCH",
  );
  const corruptCount = {
    ...expected,
    results: 2,
    profile: [{ ...expected.profile[0], results: 2 }],
  };
  assert.equal(classifyCompactFraming(corruptCount, undefined, original).status, "MISMATCH");
});

test("mixed execution metadata across otherwise valid candidates remains indeterminate", () => {
  const a = unit(values, { executionTime: "<t1>" });
  const b = unit(values, { executionTime: "<t2>" });
  const expected = compactFramingStep(row("rest", [a]), "read");
  const alternative = compactFramingStep(row("rest", [b]), "read");
  const mixed = row("rest", [
    unit(values.slice(0, 1)),
    unit(values.slice(1), { executionTime: "<t2>" }),
  ]);
  assert.equal(classifyCompactFraming(expected, alternative, mixed).status, "INDETERMINATE");
});

test("a failed terminal status cannot be admitted even by a forged fixture", () => {
  const successful = row("grpc", [unit(values)]);
  const expected = compactFramingStep(successful, "read");
  const failed = row("grpc", [unit(values)], true);
  const headDigest = createHash("sha256")
    .update(JSON.stringify({ code: 13, transport: "grpc" }))
    .digest("hex");
  assert.equal(
    classifyCompactFraming({ ...expected, headDigest }, undefined, failed).status,
    "MISMATCH",
  );
});
