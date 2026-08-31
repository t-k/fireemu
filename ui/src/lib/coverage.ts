// Flattens the official :ruleCoverage report tree into a table the Rules page renders: one row
// per source position, deepest-first order preserved, with a short reading of the values that
// position took. A position that was reached but raised, or was never reached, is shown as such
// so a reader can see which rules a request exercised. This is a pure transform (no runtime
// state), so it is unit-tested.

import type { CoverageNode, CoverageValue, RuleCoverage } from "../api/control";

/** One flattened coverage row. */
export type CoverageRow = {
  line: number;
  column: number;
  /** A short reading of the values the expression took, "not reached" when it took none. */
  summary: string;
  /** Whether the expression was evaluated at least once. */
  reached: boolean;
};

/** How one recorded value reads: short, never a whole document. */
const describeValue = (v: CoverageValue): string => {
  if (v.undefined !== undefined) return `undefined: ${v.undefined.causeMessage}`;
  if (v.boolValue !== undefined) return String(v.boolValue);
  if (v.intValue !== undefined) return v.intValue;
  if (v.floatValue !== undefined) return String(v.floatValue);
  if (v.stringValue !== undefined) return JSON.stringify(v.stringValue);
  if (v.typeValue !== undefined) return v.typeValue;
  return "null";
};

const rowOf = (node: CoverageNode): CoverageRow => {
  const values = node.values ?? [];
  return {
    line: node.sourcePosition.line,
    column: node.sourcePosition.column,
    reached: values.length > 0,
    summary:
      values.length === 0
        ? "not reached"
        : values.map((v) => `${describeValue(v.value)} ×${v.count}`).join(", "),
  };
};

/** Depth-first flatten of the report tree into rows, children before the node's siblings. */
export const coverageRows = (report: CoverageNode[]): CoverageRow[] => {
  const rows: CoverageRow[] = [];
  const walk = (nodes: CoverageNode[]): void => {
    for (const node of nodes) {
      rows.push(rowOf(node));
      if (node.children) walk(node.children);
    }
  };
  walk(report);
  return rows;
};

/** The reached / total expression counts for the coverage summary line. */
export const coverageSummary = (c: RuleCoverage): { reached: number; total: number } => {
  const rows = coverageRows(c.report);
  return { reached: rows.filter((r) => r.reached).length, total: rows.length };
};
