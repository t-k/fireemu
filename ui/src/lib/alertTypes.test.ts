import { describe, expect, it } from "vitest";
import { ALERT_TYPES, examplePayload } from "./alertTypes";

describe("alert types", () => {
  it("lists the official alerttype values grouped by product", () => {
    const values = ALERT_TYPES.map((a) => a.alerttype);
    expect(values).toContain("crashlytics.newFatalIssue");
    expect(values).toContain("billing.planUpdate");
    expect(values).toContain("performance.threshold");
    expect(new Set(values).size).toBe(values.length);
  });

  it("gives a crashlytics fatal-issue payload the handler can read", () => {
    const p = examplePayload("crashlytics.newFatalIssue") as {
      payload: { issue: { id: string; title: string } };
    };
    expect(p.payload.issue.id).toBeTruthy();
    expect(p.payload.issue.title).toBeTruthy();
  });

  it("gives every type at least a createTime and payload skeleton", () => {
    for (const { alerttype } of ALERT_TYPES) {
      const p = examplePayload(alerttype) as { createTime: string; payload: unknown };
      expect(p.createTime).toBeTruthy();
      expect(p.payload).toBeDefined();
    }
  });
});
