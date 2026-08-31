import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession } from "./helpers";

// The functions project registers `onFatalIssue = onNewFatalIssuePublished(...)`, which writes
// alerts/{issue.id} when a crashlytics.newFatalIssue alert fires. Publishing one through the UI
// must reach it, exactly as the official UI's alert workflow would.
test.describe("Alerts", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("publishes a Firebase alert that fires the registered handler", async ({
    page,
    request,
  }) => {
    await gotoApp(page, "/alerts");
    // The default type is billing; switch to the one the project handles and give it an id.
    await page.getByTestId("alert-type").selectOption("crashlytics.newFatalIssue");
    await page.getByTestId("alert-payload").fill(
      JSON.stringify({
        createTime: "2026-08-29T12:00:00Z",
        payload: { issue: { id: "ui-alert-issue", title: "Boom" } },
      }),
    );
    await page.getByTestId("alert-publish").click();
    // At least one handler received it.
    await expect(page.getByRole("status").filter({ hasNotText: "Loading" })).toContainText(
      "handler(s) received",
    );

    // Let the delivery run, then read the document the handler wrote.
    await api(request, "POST", "control/v1/sessions/default:awaitIdle", { timeoutSeconds: 30 });
    const doc = (await api(
      request,
      "GET",
      "firestore/v1/projects/demo-app/databases/(default)/documents/alerts/ui-alert-issue",
    )) as { fields?: { title?: { stringValue?: string } } };
    expect(doc.fields?.title?.stringValue).toBe("Boom");
  });
});
