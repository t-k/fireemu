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

describe("formatQuantity boundaries", () => {
  it("scales at exactly 1024 and picks digits by magnitude", () => {
    expect(formatQuantity(0, "bytes")).toBe("0 B");
    expect(formatQuantity(1023, "bytes")).toBe("1023 B");
    expect(formatQuantity(1024, "bytes")).toBe("1.00 KiB");
    expect(formatQuantity(1024 * 9.995, "bytes")).toBe("9.99 KiB");
    expect(formatQuantity(1024 * 10, "bytes")).toBe("10.0 KiB");
    expect(formatQuantity(1024 * 99.94, "bytes")).toBe("99.9 KiB");
    expect(formatQuantity(1024 * 100, "bytes")).toBe("100 KiB");
    expect(formatQuantity(1024 ** 2, "bytes")).toBe("1.00 MiB");
    expect(formatQuantity(1024 ** 3, "bytes")).toBe("1.00 GiB");
    expect(formatQuantity(1024 ** 4, "bytes")).toBe("1.00 TiB");
    expect(formatQuantity(1024 ** 5, "bytes")).toBe("1024 TiB");
    expect(formatQuantity(1024 ** 6, "bytes")).toBe("1048576 TiB");
    expect(formatQuantity(1024, "count")).toBe("1024");
  });
});

describe("saturation boundaries", () => {
  const gauge = (current: number, limit: number | null) => ({
    id: "g",
    measure: "logical" as const,
    unit: "count" as const,
    current,
    limit,
    reclaimable: 0,
  });
  it("answers null without a usable limit and clamps at 100", () => {
    expect(saturation(gauge(1, null))).toBeNull();
    expect(saturation(gauge(1, 0))).toBeNull();
    expect(saturation(gauge(1, -5))).toBeNull();
    expect(saturation(gauge(1, 3))).toBe(33);
    expect(saturation(gauge(0, 3))).toBe(0);
    expect(saturation(gauge(6, 3))).toBe(100);
  });
});

describe("needsAttention", () => {
  const base = report();
  const quiet = (): ResourceReport => ({
    ...base,
    services: base.services.map((s) => ({
      ...s,
      gauges: s.gauges.map((g) => ({ ...g, current: 0 })),
      roots: {
        ...s.roots,
        truncated: false,
        items: s.roots.items.map((r) => ({ ...r, outstanding: false })),
      },
    })),
  });
  it("is quiet only when every service is quiet", () => {
    expect(needsAttention(quiet())).toBe(false);
    const q = quiet();
    expect(needsAttention({ ...q, complete: false })).toBe(true);
    const oneOutstanding = quiet();
    oneOutstanding.services[1]!.roots.items = [
      { kind: "k", id: "i", count: 1, bytes: 1, outstanding: true },
    ];
    expect(needsAttention(oneOutstanding)).toBe(true);
    const oneTruncated = quiet();
    oneTruncated.services[1]!.roots.truncated = true;
    expect(needsAttention(oneTruncated)).toBe(true);
    const oneSaturated = quiet();
    oneSaturated.services[0]!.gauges[0]!.current = 1024;
    expect(needsAttention(oneSaturated)).toBe(true);
  });
});

describe("parseAllowances lines", () => {
  it("reports the 1-based line of the first malformed entry", () => {
    expect(parseAllowances("firestore transactions t1 kept on purpose")).toEqual({
      ok: true,
      allow: [{ service: "firestore", kind: "transactions", id: "t1", reason: "kept on purpose" }],
    });
    expect(parseAllowances("# c\n\n  a b c d  \nx y z")).toEqual({ ok: false, line: 4 });
    expect(parseAllowances("a b c d\n\n\nx y z")).toEqual({ ok: false, line: 4 });
    expect(parseAllowances("a  b\tc   d e")).toEqual({
      ok: true,
      allow: [{ service: "a", kind: "b", id: "c", reason: "d e" }],
    });
    expect(parseAllowances("")).toEqual({ ok: true, allow: [] });
    expect(parseAllowances("\n#only\n")).toEqual({ ok: true, allow: [] });
  });
});
