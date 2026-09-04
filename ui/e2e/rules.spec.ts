import { expect, test } from "@playwright/test";
import { PORTS } from "./global-setup";
import { api, gotoApp } from "./helpers";

/**
 * A Firestore REST call straight at the daemon's Firestore port, with no credential, so
 * Security Rules actually decide it. The UI's own proxy calls Firestore as the owner, which
 * bypasses rules and would record no decision.
 */
const asClient = (method: string, path: string, body?: unknown): Promise<Response> =>
  fetch(`http://127.0.0.1:${PORTS.firestore}/v1/projects/demo-app/databases/(default)/${path}`, {
    method,
    ...(body === undefined
      ? {}
      : { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
  });

const RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read: if true; allow write: if false; }
  }
}`;

test.describe("Rules", () => {
  test.afterEach(async ({ request }) => {
    await api(request, "DELETE", "control/v1/rules");
  });

  test("replaces and drops the Firestore rules", async ({ page, request }) => {
    await gotoApp(page, "/rules");
    await expect(page.getByText("Not loaded: every request is allowed").first()).toBeVisible();
    await page.locator("#rules-firestore").fill(RULES);
    await page.getByTestId("rules-firestore-save").click();
    await expect(page.getByRole("status").filter({ hasNotText: "Loading" })).toContainText(
      "Rules replaced",
    );
    await expect(page.getByText("Loaded", { exact: true }).first()).toBeVisible();
    const info = (await api(request, "GET", "control/v1/rules")) as { loaded: boolean };
    expect(info.loaded).toBe(true);
    await page.locator("#rules-firestore").fill("service cloud.firestore { match");
    await page.getByTestId("rules-firestore-save").click();
    await expect(page.getByRole("alert")).toContainText("do not parse");
    await page.getByTestId("rules-firestore-drop").click();
    await page.getByTestId("rules-firestore-drop-confirm").click();
    await expect(page.getByText("Not loaded: every request is allowed").first()).toBeVisible();
  });

  test("lists the requests Security Rules decided and their per-expression traces", async ({
    page,
    request,
  }) => {
    await api(request, "PUT", "control/v1/rules", { source: RULES });
    await gotoApp(page, "/rules");
    // The first requests query enables the bounded trace ring. Open the UI before producing
    // the decisions whose traces this scenario expects to inspect.
    await expect(
      page.getByText("No request has been decided against the loaded rules yet."),
    ).toBeVisible();
    // One read the rules allow and one write they deny, decided by the ruleset just loaded.
    expect((await asClient("GET", "documents/traced/a")).status).toBe(404);
    expect(
      (await asClient("PATCH", "documents/traced/a", { fields: { n: { integerValue: "1" } } }))
        .status,
    ).toBe(403);

    await page.getByTestId("rules-requests-refresh").click();
    const rows = page.getByTestId("rules-requests").locator("tbody tr");
    await expect(rows).toHaveCount(2);
    // Newest first: the denied write, then the allowed read.
    await expect(rows.nth(0)).toContainText("traced/a");
    await expect(rows.nth(0)).toContainText("Denied");
    await expect(rows.nth(1)).toContainText("Allowed");

    // The trace names each expression by its position and the values it took.
    await rows.nth(1).getByRole("button", { name: "Trace" }).click();
    const trace = page.getByTestId("rules-request-expressions");
    await expect(trace).toBeVisible();
    await expect(trace).toContainText("4:");
    await expect(trace).toContainText("true x1");
  });
  test("renders the :ruleCoverage report -- positions, values and the reached count", async ({
    page,
    request,
  }) => {
    await api(request, "PUT", "control/v1/rules", { source: RULES });
    // Exercise the ruleset so coverage has values to report.
    expect((await asClient("GET", "documents/traced/a")).status).toBe(404);
    expect(
      (await asClient("PATCH", "documents/traced/a", { fields: { n: { integerValue: "1" } } }))
        .status,
    ).toBe(403);

    await gotoApp(page, "/rules");
    await page.getByTestId("rules-coverage-refresh").click();
    await expect(page.getByTestId("rules-coverage-summary")).toContainText(
      "expressions were evaluated",
    );
    const rows = page.getByTestId("rules-coverage").locator("tbody tr");
    await expect(rows.first()).toBeVisible();
    // At least one position was reached and reads as a boolean the rule evaluated.
    await expect(page.getByTestId("rules-coverage")).toContainText("true");
  });
});
