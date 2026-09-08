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

describe("alert type inventory", () => {
  it("is exactly the SDK's list, grouped by product in declaration order", () => {
    expect(ALERT_TYPES).toEqual([
      { alerttype: "billing.planUpdate", product: "Billing" },
      { alerttype: "billing.planAutomatedUpdate", product: "Billing" },
      { alerttype: "crashlytics.newFatalIssue", product: "Crashlytics" },
      { alerttype: "crashlytics.newNonfatalIssue", product: "Crashlytics" },
      { alerttype: "crashlytics.regression", product: "Crashlytics" },
      { alerttype: "crashlytics.stabilityDigest", product: "Crashlytics" },
      { alerttype: "crashlytics.velocity", product: "Crashlytics" },
      { alerttype: "crashlytics.newAnrIssue", product: "Crashlytics" },
      { alerttype: "appDistribution.newTesterIosDevice", product: "App Distribution" },
      { alerttype: "appDistribution.inAppFeedback", product: "App Distribution" },
      { alerttype: "performance.threshold", product: "Performance" },
    ]);
  });

  it("gives exact example payloads", () => {
    expect(examplePayload("crashlytics.newFatalIssue")).toEqual({
      createTime: "2026-08-29T12:00:00Z",
      payload: { issue: { id: "issue-1", title: "NullPointerException in MainActivity" } },
    });
    expect(examplePayload("billing.planUpdate")).toEqual({
      createTime: "2026-08-29T12:00:00Z",
      payload: {},
    });
  });
});
