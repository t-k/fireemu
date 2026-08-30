import { expect, test } from "@playwright/test";
import { api, gotoApp } from "./helpers";

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
});
