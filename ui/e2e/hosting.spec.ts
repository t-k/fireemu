import { expect, test } from "@playwright/test";
import { gotoApp } from "./helpers";

test.describe("Hosting", () => {
  test("is reachable from the navigation and says when no site is served", async ({ page }) => {
    await gotoApp(page, "/");
    await page.getByRole("link", { name: "Hosting" }).click();
    await expect(page.getByRole("heading", { name: "Hosting", exact: true })).toBeVisible();
    // The smoke project has no hosting block, so the page says so instead of showing an empty site.
    await expect(page.getByTestId("hosting-not-served")).toContainText("firebase.json");
    await expect(page.getByTestId("hosting-url")).toHaveCount(0);
  });
});
