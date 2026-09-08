import { describe, expect, it } from "vitest";
import { coverageRows, coverageSummary } from "./coverage";
import type { RuleCoverage } from "../api/control";

const sample: RuleCoverage = {
  rules: { files: [{ name: "firestore.rules", content: "rules_version = '2';" }] },
  report: [
    {
      sourcePosition: { line: 5, column: 22, currentOffset: 100, endOffset: 130 },
      values: [{ value: { boolValue: true }, count: 3 }],
      children: [
        {
          sourcePosition: { line: 5, column: 30, currentOffset: 108, endOffset: 120 },
          values: [{ value: { stringValue: "alice" }, count: 3 }],
        },
      ],
    },
    {
      // reached but raised
      sourcePosition: { line: 6, column: 10, currentOffset: 140, endOffset: 150 },
      values: [{ value: { undefined: { causeMessage: "property is undefined" } }, count: 1 }],
    },
    {
      // never reached
      sourcePosition: { line: 7, column: 4, currentOffset: 160, endOffset: 170 },
    },
  ],
};

describe("rule coverage", () => {
  it("flattens the report tree depth-first, children before siblings", () => {
    const rows = coverageRows(sample.report);
    expect(rows.map((r) => `${r.line}:${r.column}`)).toEqual(["5:22", "5:30", "6:10", "7:4"]);
  });

  it("reads bool, string and undefined values and marks unreached expressions", () => {
    const [bool, string, raised, unreached] = coverageRows(sample.report);
    expect(bool?.summary).toBe("true ×3");
    expect(string?.summary).toBe('"alice" ×3');
    expect(raised?.summary).toContain("undefined: property is undefined");
    expect(raised?.reached).toBe(true);
    expect(unreached?.summary).toBe("not reached");
    expect(unreached?.reached).toBe(false);
  });

  it("counts reached over total expressions", () => {
    expect(coverageSummary(sample)).toEqual({ reached: 3, total: 4 });
  });
});

describe("value readings", () => {
  const row = (value: object) =>
    coverageRows([
      {
        sourcePosition: { line: 1, column: 1, currentOffset: 0, endOffset: 1 },
        values: [{ value, count: 2 }],
      },
    ])[0]!.summary;
  it("reads every value kind, in priority order, and null for an empty value", () => {
    expect(row({ intValue: "7" })).toBe("7 ×2");
    expect(row({ floatValue: 1.5 })).toBe("1.5 ×2");
    expect(row({ typeValue: "map" })).toBe("map ×2");
    expect(row({})).toBe("null ×2");
    expect(row({ boolValue: false })).toBe("false ×2");
    expect(row({ intValue: "1", typeValue: "int" })).toBe("1 ×2");
    expect(row({ stringValue: "", typeValue: "string" })).toBe('"" ×2');
    expect(row({ floatValue: 0, stringValue: "s" })).toBe("0 ×2");
  });
  it("joins several values of one expression", () => {
    const rows = coverageRows([
      {
        sourcePosition: { line: 1, column: 1, currentOffset: 0, endOffset: 1 },
        values: [
          { value: { boolValue: true }, count: 1 },
          { value: { boolValue: false }, count: 3 },
        ],
      },
    ]);
    expect(rows[0]!.summary).toBe("true ×1, false ×3");
  });
});
