import { describe, expect, it } from "vitest";
import {
  formatQuantity,
  needsAttention,
  parseAllowances,
  saturation,
  summarize,
  type ResourceReport,
} from "./resources";

const report = (overrides: Partial<ResourceReport> = {}): ResourceReport => ({
  schemaVersion: 1,
  session: "default",
  project: "demo-app",
  complete: true,
  rootBudget: 64,
  services: [
    {
      service: "firestore",
      gauges: [
        {
          id: "history.session_bytes",
          measure: "logical",
          unit: "bytes",
          current: 512,
          limit: 1024,
          reclaimable: 0,
        },
        {
          id: "transactions.active",
          measure: "logical",
          unit: "count",
          current: 1,
          limit: null,
          reclaimable: 0,
        },
      ],
      refusals: [{ reason: "history.session_versions", count: 3 }],
      roots: {
        total: 2,
        truncated: false,
        items: [
          { kind: "database", id: "demo-app/(default)", count: 4, bytes: 512, outstanding: false },
          {
            kind: "transactions",
            id: "demo-app/(default)",
            count: 1,
            bytes: 16,
            outstanding: true,
          },
        ],
      },
    },
    {
      service: "snapshots",
      gauges: [
        {
          id: "snapshots.retained",
          measure: "logical",
          unit: "count",
          current: 8,
          limit: 8,
          reclaimable: 0,
        },
      ],
      refusals: [],
      roots: { total: 0, truncated: false, items: [] },
    },
  ],
  errors: [],
  ...overrides,
});

describe("resource report summaries", () => {
  it("formats bytes in binary units and counts as integers", () => {
    expect(formatQuantity(0, "bytes")).toBe("0 B");
    expect(formatQuantity(1023, "bytes")).toBe("1023 B");
    expect(formatQuantity(1536, "bytes")).toBe("1.50 KiB");
    expect(formatQuantity(15 * 1024 * 1024, "bytes")).toBe("15.0 MiB");
    expect(formatQuantity(3 * 1024 ** 3, "bytes")).toBe("3.00 GiB");
    expect(formatQuantity(120 * 1024, "bytes")).toBe("120 KiB");
    expect(formatQuantity(42, "count")).toBe("42");
  });

  it("reports saturation only against a positive limit", () => {
    const [firestore] = report().services;
    expect(saturation(firestore!.gauges[0]!)).toBe(50);
    expect(saturation(firestore!.gauges[1]!)).toBeNull();
    expect(
      saturation({
        id: "x",
        measure: "logical",
        unit: "count",
        current: 5,
        limit: 2,
        reclaimable: 0,
      }),
    ).toBe(100);
  });

  it("summarizes outstanding roots, saturated gauges and refusals per service", () => {
    expect(summarize(report())).toEqual([
      {
        service: "firestore",
        outstanding: 1,
        saturated: [],
        refused: 3,
        truncated: false,
      },
      {
        service: "snapshots",
        outstanding: 0,
        saturated: ["snapshots.retained"],
        refused: 0,
        truncated: false,
      },
    ]);
  });

  it("needs attention for outstanding roots, saturation, truncation or an incomplete report", () => {
    expect(needsAttention(report())).toBe(true);
    const calm = report();
    calm.services[0]!.roots.items = calm.services[0]!.roots.items.filter((r) => !r.outstanding);
    calm.services[1]!.gauges[0]!.current = 1;
    expect(needsAttention(calm)).toBe(false);
    expect(needsAttention({ ...calm, complete: false })).toBe(true);
    const truncated = report();
    truncated.services[1]!.roots.truncated = true;
    expect(needsAttention(truncated)).toBe(true);
  });

  it("parses one allowance per line and reports the offending line", () => {
    expect(
      parseAllowances(
        "# held by the test\nfirestore transactions demo-app/(default) the test holds it open\n\nfunctions invocation inv-1 slow handler\n",
      ),
    ).toEqual({
      ok: true,
      allow: [
        {
          service: "firestore",
          kind: "transactions",
          id: "demo-app/(default)",
          reason: "the test holds it open",
        },
        { service: "functions", kind: "invocation", id: "inv-1", reason: "slow handler" },
      ],
    });
    expect(parseAllowances("firestore transactions demo-app/(default)")).toEqual({
      ok: false,
      line: 1,
    });
    expect(parseAllowances("\nok kind id reason\nbroken line")).toEqual({ ok: false, line: 3 });
    expect(parseAllowances("")).toEqual({ ok: true, allow: [] });
  });
});
