// The Firebase alert types an onAlertPublished handler can register for, exactly the alerttype
// values firebase-functions/v2/alerts publishes (the eventFilters `alerttype`). Grouped by the
// product that emits them, in the order the SDK declares them. A pure list, unit-tested.

/** One official alert type: its alerttype value and the product that emits it. */
export type AlertType = { alerttype: string; product: string };

export const ALERT_TYPES: readonly AlertType[] = [
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
];

/**
 * A minimal, editable example payload for an alert type: the `data.payload` shape a handler of
 * that type reads. Only the fields the emulator's own smoke handler needs are filled with
 * examples; every alert also carries a `createTime`. The user edits this before publishing.
 */
export const examplePayload = (alerttype: string): unknown => {
  const createTime = "2026-08-29T12:00:00Z";
  if (alerttype === "crashlytics.newFatalIssue") {
    return {
      createTime,
      payload: {
        issue: { id: "issue-1", title: "NullPointerException in MainActivity" },
      },
    };
  }
  return { createTime, payload: {} };
};
